import * as S3 from "@aws-sdk/client-s3";
import * as HttpServerRequest from "@effect/platform/HttpServerRequest";
import { Effect } from "effect";
import { describe, expect, it, vi } from "vitest";

import {
	createS3BucketAccess,
	getRequestAccessibleS3Endpoint,
} from "../../../../packages/web-backend/src/S3Buckets/S3BucketAccess";
import { S3BucketClientProvider } from "../../../../packages/web-backend/src/S3Buckets/S3BucketClientProvider";

describe("getRequestAccessibleS3Endpoint", () => {
	it("replaces a loopback endpoint host for a private network request", () => {
		expect(
			getRequestAccessibleS3Endpoint(
				"http://localhost:9000",
				"http://10.0.0.42:3000/api/mobile/caps",
			),
		).toBe("http://10.0.0.42:9000");
	});

	it("keeps loopback endpoints unchanged for loopback requests", () => {
		expect(
			getRequestAccessibleS3Endpoint(
				"http://localhost:9000",
				"http://localhost:3000/api/mobile/caps",
			),
		).toBeNull();
	});

	it("does not rewrite remote storage endpoints", () => {
		expect(
			getRequestAccessibleS3Endpoint(
				"https://storage.example.com",
				"http://10.0.0.42:3000/api/mobile/caps",
			),
		).toBeNull();
	});

	it("does not rewrite loopback storage for a public request host", () => {
		expect(
			getRequestAccessibleS3Endpoint(
				"http://localhost:9000",
				"https://cap.example.com/api/mobile/caps",
			),
		).toBeNull();
	});

	it("signs public object URLs for the request-accessible endpoint", async () => {
		const client = new S3.S3Client({
			credentials: {
				accessKeyId: "test-access-key",
				secretAccessKey: "test-secret-key",
			},
			endpoint: "http://localhost:9000",
			forcePathStyle: true,
			region: "us-east-1",
		});

		try {
			const access = await Effect.runPromise(
				createS3BucketAccess.pipe(
					Effect.provideService(S3BucketClientProvider, {
						bucket: "capso",
						getInternal: Effect.succeed(client),
						getPublic: Effect.succeed(client),
						isPathStyle: true,
					}),
				),
			);
			const request = HttpServerRequest.fromWeb(
				new Request("http://10.0.0.42:3000/api/mobile/caps"),
			);
			const signedUrl = await Effect.runPromise(
				access
					.getSignedObjectUrl("video/video.mp4")
					.pipe(
						Effect.provideService(HttpServerRequest.HttpServerRequest, request),
					),
			);

			expect(new URL(signedUrl)).toMatchObject({
				hostname: "10.0.0.42",
				port: "9000",
			});
			expect(signedUrl).toContain("X-Amz-Signature=");
		} finally {
			client.destroy();
		}
	});
});

describe("S3 object streaming", () => {
	async function fixture() {
		const client = new S3.S3Client({
			credentials: { accessKeyId: "test-key", secretAccessKey: "test-secret" },
			region: "us-east-1",
		});
		const send = vi.spyOn(client, "send");
		const access = await Effect.runPromise(
			createS3BucketAccess.pipe(
				Effect.provideService(S3BucketClientProvider, {
					bucket: "private-videos",
					getInternal: Effect.succeed(client),
					getPublic: Effect.die("Public storage must not be used"),
					isPathStyle: false,
				}),
			),
		);
		return { access, send };
	}

	it("returns a stream before the full object is available", async () => {
		const { access, send } = await fixture();
		let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
		const stream = new ReadableStream<Uint8Array>({
			start(value) {
				controller = value;
			},
		});
		send.mockImplementation(async () => ({
			Body: { transformToWebStream: () => stream },
			ContentType: "video/mp4",
			ContentLength: 4,
			$metadata: { httpStatusCode: 200 },
		}));
		const response = await Effect.runPromise(
			access.getObjectResponse("video.mp4"),
		);
		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toBe("video/mp4");
		expect(response.headers.get("Content-Length")).toBe("4");
		expect(response.headers.get("Accept-Ranges")).toBe("bytes");
		expect(response.body).toBe(stream);
		controller?.enqueue(new TextEncoder().encode("data"));
		controller?.close();
		expect(await response.text()).toBe("data");
	});

	it("passes range, exact identity, and cancellation to the internal client", async () => {
		const { access, send } = await fixture();
		const controller = new AbortController();
		send.mockImplementation(async () => ({
			Body: { transformToWebStream: () => new Response("data").body },
			ContentType: "video/mp4",
			ContentLength: 4,
			ContentRange: "bytes 10-13/100",
			$metadata: { httpStatusCode: 206 },
		}));
		const response = await Effect.runPromise(
			access.getObjectResponse("video.mp4", "bytes=10-13", {
				objectIdentity: '"version-1"',
				signal: controller.signal,
			}),
		);
		expect(send).toHaveBeenCalledWith(
			expect.objectContaining({
				input: {
					Bucket: "private-videos",
					Key: "video.mp4",
					Range: "bytes=10-13",
					IfMatch: '"version-1"',
				},
			}),
			{ abortSignal: controller.signal },
		);
		expect(response.status).toBe(206);
		expect(response.headers.get("Content-Range")).toBe("bytes 10-13/100");
		expect(await response.text()).toBe("data");
		controller.abort();
		expect(send.mock.calls[0]?.[1]?.abortSignal?.aborted).toBe(true);
	});

	it.each([404, 412, 416])(
		"preserves safe storage status %s",
		async (status) => {
			const { access, send } = await fixture();
			send.mockRejectedValue(
				new S3.S3ServiceException({
					name: "StorageFailure",
					$fault: "client",
					$metadata: { httpStatusCode: status },
					message: "Private provider detail",
				}),
			);
			const response = await Effect.runPromise(
				access.getObjectResponse("video.mp4"),
			);
			expect(response.status).toBe(status);
			expect(await response.text()).toBe("");
		},
	);

	it("propagates unexpected storage failures", async () => {
		const { access, send } = await fixture();
		send.mockRejectedValue(new Error("Storage offline"));
		await expect(
			Effect.runPromise(access.getObjectResponse("video.mp4")),
		).rejects.toThrow();
	});

	it("does not silently return an empty video when storage omits the body", async () => {
		const { access, send } = await fixture();
		send.mockImplementation(async () => ({
			$metadata: { httpStatusCode: 200 },
		}));
		await expect(
			Effect.runPromise(access.getObjectResponse("video.mp4")),
		).rejects.toThrow();
	});
});
