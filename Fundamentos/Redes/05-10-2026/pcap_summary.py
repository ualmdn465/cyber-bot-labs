from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR
from tabulate import tabulate
import sys

def obtener_protocolo(pkt):
	if pkt.haslayer(DNS):
		return "DNS"
	elif pkt.haslayer(TCP):
		return "TCP"
	elif pkt.haslayer(UDP):
		return "UDP"
	elif pkt.haslayer(ICMP):
		return "ICMP"
	elif pkt.haslayer(ARP):
		return "ARP"
	elif pkt.haslayer(IPv6):
		return "IPv6"
	elif pkt.haslayer(IP):
		return "IP"
	return "Otro"

def obtener_direcciones(pkt):
	if pkt.haslayer(IP):
		origen = pkt[IP].src
		destino = pkt[IP].dst
	elif pkt.haslayer(IPv6):
		origen = pkt[IPv6].src
		destino = pkt[IPv6].dst
	elif pkt.haslayer(ARP):
		origen = pkt[ARP].psrc
		destino = pkt[ARP].pdst
	else:
		origen = getattr(pkt, "src", "Desconocido")
		destino = getattr(pkr, "dst", "Desconocido")

	return f"{origen} -> {destino}"

def obtener_nombre_dns(pkt):
	if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
		dns = pkt[DNS]

		if dns.qr == 0:
			nombre = pkt[DNSQR].qname

			if isinstance(nombre, bytes):
				nombre = nombre.decode("utf-8", errors="replace")

			return nombre.rstrip(".")

	return "-"

def analizar_pcap(ruta):
	try:
		paquetes = rdpcap(ruta)
	except (OSError, Exception) as error:
		print(f"Error al leer el archivo: {error}")
		return

	filas = []

	for numero, pkt in enumerate(paquetes, start=1):
		filas.append([
			str(numero),
			obtener_protocolo(pkt),
			obtener_direcciones(pkt),
			obtener_nombre_dns(pkt)
		])

	print(tabulate(
		filas,
		headers=["Nº", "Protocolo", "Origen->Destino", "Nombre DNS"],
		tablefmt="grid",
		stralign="left"
	))

	print(f"\nTotal de paquetes analizados: {filas}")

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print(f"Uso: python3 {sys.argv[0]} archivo.pcap")
		sys.exit(1)

	analizar_pcap(sys.argv[1])
