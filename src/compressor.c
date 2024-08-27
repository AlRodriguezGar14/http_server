#include "server.h"
/**
 * Compresses the given data using the gzip compression algorithm.
 *
 * @param src Pointer to the data to be compressed.
 * @param src_len Length of the data to be compressed.
 * @param dst Pointer to a pointer where the compressed data will be stored.
 *            This function will allocate memory for the compressed data,
 *            and it's the caller's responsibility to free this memory when it's
 * no longer needed.
 * @param dst_len Pointer to an integer where the length of the compressed data
 * will be stored.
 *
 * @return 0 if the compression was successful, -1 if an error occurred.
 *
 * The function uses the zlib library to perform the compression. It initializes
 * a z_stream structure, then repeatedly calls deflate() to compress the data in
 * chunks until all data has been compressed. If the output buffer becomes full,
 * it is reallocated to double its size. After all data has been compressed,
 * deflateEnd() is called to clean up and free any memory allocated by zlib.
 */

int gzip_compress(const char *src, int src_len, char **dst, int *dst_len) {
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
					 Z_DEFAULT_STRATEGY) != Z_OK) {
		return -1;
	}

	int chunk = CHUNK;
	*dst = malloc(chunk);
	if (*dst == NULL) {
		deflateEnd(&strm);
		return -1;
	}

	*dst_len = 0;
	strm.avail_in = src_len;
	strm.next_in = (Bytef *)src;
	int deflate_res;

	while (42) {
		strm.avail_out = chunk - *dst_len;
		strm.next_out = (Bytef *)(*dst + *dst_len);

		deflate_res = deflate(&strm, Z_FINISH);
		if (deflate_res == Z_STREAM_ERROR) {
			free(*dst);
			deflateEnd(&strm);
			return -1;
		}

		int have = chunk - *dst_len - strm.avail_out;
		*dst_len += have;

		if (deflate_res == Z_STREAM_END) {
			break;
		}

		if (strm.avail_out == 0) {
			chunk *= 2;
			char *new_dst = realloc(*dst, chunk);
			if (new_dst == NULL) {
				free(*dst);
				deflateEnd(&strm);
				return -1;
			}
			*dst = new_dst;
		}
	}

	deflateEnd(&strm);
	return 0;
}
