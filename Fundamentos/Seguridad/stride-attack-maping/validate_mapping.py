import csv
import re
import sys
from pathlib import Path
TECHNIQUE_PATTERN = re.compile(r"T[0-9]{4}(\.[0-9]{3})?")

def main() -> int:
	if len(sys.argv) != 2:
		print(
			f"Uso: python {Path(sys.argv[0]).name} mapping.csv",
			file=sys.stderr,
		)
		return 2
	csv_path = Path(sys.argv[1])

	if not csv_path.is_file():
		print(f"Error: no existe el archivo: {csv_path}", file=sys.stderr)
		return 2

	errors = 0

	try:
		with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
			reader = csv.DictReader(file)

			if not reader.fieldnames or "tecnica_id" not in reader.fieldnames:
				print(
					"Error: el CSV debe contener una columna 'tecnica_id'.",
					file=sys.stderr,
				)
				return 2

			for row in reader:
				line_number = reader.line_num
				technique_id = (row.get("tecnica_id") or "").strip()

				if not TECHNIQUE_PATTERN.fullmatch(technique_id):
					print(
						f"Error en la linea {line_number}: "
						f"tecnica_id inválido: {technique_id!r}. "
						"Formato esperado: T#### o T####.### "
						"(ejemplos: T1190, T1499.003).",
						file=sys.stderr,
					)
					errors += 1


	except (OSError, UnicodeError, csv.Error) as exc:
		print(f"Error al leer el CSV: {exc}", file=sys.stderr)
		return 2

	if errors:
		print(
			f"Validación fallida: {errors} error(es).",
			file=sys.stderr,
		)
		return 1

	print(f"Validación correcta: {csv_path}")
	return 0

if __name__ == "__main__":
	sys.exit(main())

