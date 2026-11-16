import { useEffect, useRef, useState } from "react";

// A confirmation in the dashboard's own idiom, not the browser's: what will happen, said plainly,
// and two buttons. Escape or the backdrop cancels.
export default function Confirm({
	title,
	children,
	action,
	danger = false,
	onConfirm,
	onCancel,
}: {
	title: string;
	children: React.ReactNode;
	action: string;
	danger?: boolean;
	onConfirm: () => void;
	onCancel: () => void;
}) {
	const cancel = useRef<HTMLButtonElement>(null);
	useEffect(() => {
		cancel.current?.focus();
		const key = (event: KeyboardEvent) => {
			if (event.key === "Escape") onCancel();
		};
		window.addEventListener("keydown", key);
		return () => window.removeEventListener("keydown", key);
	}, [onCancel]);

	return (
		<div className="dialog-backdrop" onClick={onCancel}>
			<div className="dialog" role="dialog" aria-modal="true" aria-label={title} onClick={event => event.stopPropagation()}>
				<h3>{title}</h3>
				<div>{children}</div>
				<div className="form-actions">
					<button type="button" className={danger ? "btn danger" : "btn primary"} onClick={onConfirm}>
						{action}
					</button>
					<button type="button" className="btn" ref={cancel} onClick={onCancel}>
						Cancel
					</button>
				</div>
			</div>
		</div>
	);
}

// A confirmation held by a screen: ask() opens it for one change, which runs only when confirmed.
export function useConfirm() {
	const [pending, setPending] = useState<{ title: string; body: React.ReactNode; action: string; danger: boolean; run: () => void } | null>(null);
	const ask = (title: string, body: React.ReactNode, action: string, run: () => void, danger = true) => setPending({ title, body, action, danger, run });
	const dialog = pending ? (
		<Confirm
			title={pending.title}
			action={pending.action}
			danger={pending.danger}
			onConfirm={() => {
				setPending(null);
				pending.run();
			}}
			onCancel={() => setPending(null)}
		>
			{pending.body}
		</Confirm>
	) : null;
	return { ask, dialog };
}
