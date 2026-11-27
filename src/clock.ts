/**
 * Time written into reports. SOURCE_DATE_EPOCH (seconds, reproducible-builds.org) pins it so equal input
 * gives equal bytes. Waiver expiry never uses this: it must follow the real date.
 */
export function stamp(): string {
  const epoch = process.env.SOURCE_DATE_EPOCH;
  return (epoch && /^\d{1,11}$/.test(epoch) ? new Date(Number(epoch) * 1000) : new Date()).toISOString();
}
