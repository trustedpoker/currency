import { formatInTimeZone } from "date-fns-tz";

export const secondsToLabel = (seconds: number): string => {
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;

  if (minutes === 0) return `${remainingSeconds} seconds`;
  if (minutes === 1) return "1 minute";
  if (remainingSeconds === 0) return `${minutes} minutes`;
  return `${minutes} minutes and ${remainingSeconds} seconds`;
};

// Convert a BigInt timestamp in nanoseconds to a Date object in the system's local time zone.
export const BigIntTimestampToDate = (timestamp: bigint) =>
  new Date(Number(timestamp / 1_000_000n));

// Convert a Date object to a BigInt timestamp in nanoseconds since the Unix epoch.
export const DateToBigIntTimestamp = (date: Date) =>
  BigInt(date.getTime()) * 1_000_000n;

// Convert a Date object to a BigInt timestamp in nanoseconds since the Unix epoch.
export const DateToBigNanoseconds = (date: Date) =>
  BigInt(date.getTime()) * 1_000_000n;

// Convert a BigInt timestamp in seconds to a local date-time string in the specified time zone.
export const DateToLocalDateTimeString = (
  timestamp: bigint,
  format = "yyyy-MM-dd HH:mm"
  // timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone
) => {
  try {
    return formatInTimeZone(
      BigIntTimestampToDate(timestamp),
      Intl.DateTimeFormat().resolvedOptions().timeZone,
      format
    );
  } catch {
    return BigIntTimestampToDate(timestamp).toISOString().slice(0, 16);
  }
};
