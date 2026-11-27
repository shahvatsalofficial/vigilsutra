/** Bytes of a text file as a string, or null for binary data. UTF-16 is recognised by its byte-order mark. */
export function decodeText(buf: Buffer): string | null {
  const le = buf[0] === 0xff && buf[1] === 0xfe;
  if (le || (buf[0] === 0xfe && buf[1] === 0xff)) {
    const body = Buffer.from(buf.subarray(2, buf.length - (buf.length % 2)));
    return (le ? body : body.swap16()).toString("utf16le");
  }
  return buf.subarray(0, 8192).includes(0) ? null : buf.toString("utf8");
}
