/**
 * Quote a CSV field and neutralise spreadsheet formula injection (OWASP: a leading = + - @, and a
 * leading tab or carriage return, which some spreadsheets strip before evaluating the rest).
 * Matches csv_field in src-tauri/src/export.rs.
 */
export function csvField(value: string): string {
  const text = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${text.replace(/"/g, '""')}"`;
}

export function csvRow(fields: string[]): string {
  return fields.map(csvField).join(",");
}
