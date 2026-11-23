import { useState, type ReactNode } from "react";

export type Detail = {
	label: string;
	value: ReactNode;
	// The text a copy button puts on the clipboard; none: no button.
	copy?: string;
	mono?: boolean;
};

// One record's fields, labelled, each value copyable where the service says it is worth copying (an
// id, a key, a topic).
export function DetailPanel({ title, details }: { title?: string; details: Detail[] }) {
	const [copied, setCopied] = useState<string | undefined>(undefined);

	const copy = async (detail: Detail) => {
		try {
			await navigator.clipboard.writeText(detail.copy!);
			setCopied(detail.label);
		} catch {
			setCopied(undefined);
		}
	};

	return (
		<section className="panel">
			{title && <h3>{title}</h3>}
			<dl className="details">
				{details.map(detail => (
					<div className="detail" key={detail.label}>
						<dt>{detail.label}</dt>
						<dd className={detail.mono ? "mono" : undefined}>
							{detail.value}
							{detail.copy !== undefined && (
								<button type="button" className="btn copy" onClick={() => copy(detail)} aria-label={`Copy ${detail.label}`}>
									{copied === detail.label ? "Copied" : "Copy"}
								</button>
							)}
						</dd>
					</div>
				))}
			</dl>
		</section>
	);
}
