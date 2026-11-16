// A QR symbol as Lugh encodes it (lugh/signin/qr.h): `size` modules a side, row by row, '1' dark;
// drawn with the four-module quiet zone a reader needs, dark on white.
export default function QrCode({ size, modules, label }: { size: number; modules: string; label: string }) {
	const quiet = 4;
	const side = size + 2 * quiet;
	const path: string[] = [];
	for (let y = 0; y < size; ++y) {
		for (let x = 0; x < size; ++x) {
			if (modules[y * size + x] === "1") path.push(`M${x + quiet} ${y + quiet}h1v1h-1z`);
		}
	}
	return (
		<svg className="qr" viewBox={`0 0 ${side} ${side}`} role="img" aria-label={label} shapeRendering="crispEdges">
			<rect width={side} height={side} fill="#ffffff" />
			<path d={path.join("")} fill="#000000" />
		</svg>
	);
}
