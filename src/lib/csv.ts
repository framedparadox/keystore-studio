/** Quote a CSV field and neutralise spreadsheet formula injection. Matches the Rust inventory writer. */
export function csvField(value: string): string {
  const text = /^[=+\-@]/.test(value) ? `'${value}` : value;
  return `"${text.replace(/"/g, '""')}"`;
}

export function csvRow(fields: string[]): string {
  return fields.map(csvField).join(",");
}
