import { useMemo, useState, type ReactNode } from "react";

export type Column<Row> = {
	key: string;
	label: string;
	// The cell; the row's field of the column's key by default.
	render?: (row: Row) => ReactNode;
	// What the column sorts by; none: the column does not sort.
	sortBy?: (row: Row) => string | number;
};

export type Paging = {
	hasPrevious: boolean;
	hasNext: boolean;
	previous: () => void;
	next: () => void;
	// Which page is shown, from 1.
	number?: number;
};

// Rows of records: sortable by any column that says how, filtered by what the person types (over the
// text the service says a row is found by), and paged by the service, by cursor (useCursorPages) or
// by page. Sorting and filtering are of the page shown; a service that sorts or filters over the
// whole list does it in the load the paging calls.
export function DataTable<Row>({
	columns,
	rows,
	rowKey,
	filterText,
	onRowClick,
	paging,
	empty = "Nothing here yet",
	label,
}: {
	columns: Column<Row>[];
	rows: Row[] | undefined;
	rowKey: (row: Row) => string;
	// The text a row is found by; none: no filter box.
	filterText?: (row: Row) => string;
	onRowClick?: (row: Row) => void;
	paging?: Paging;
	empty?: string;
	label?: string;
}) {
	const [filter, setFilter] = useState("");
	const [sort, setSort] = useState<{ key: string; descending: boolean } | undefined>(undefined);

	const shown = useMemo(() => {
		let out = rows ?? [];
		if (filterText && filter) {
			const wanted = filter.toLowerCase();
			out = out.filter(row => filterText(row).toLowerCase().includes(wanted));
		}
		const by = sort && columns.find(column => column.key === sort.key)?.sortBy;
		if (by && sort) {
			out = [...out].sort((a, b) => {
				const x = by(a);
				const y = by(b);
				const order = x < y ? -1 : x > y ? 1 : 0;
				return sort.descending ? -order : order;
			});
		}
		return out;
	}, [rows, filter, filterText, sort, columns]);

	const sortOn = (key: string) => setSort(sort?.key === key ? { key, descending: !sort.descending } : { key, descending: false });

	return (
		<div className="data-table-frame">
			{filterText && <input className="table-filter" placeholder="Find" value={filter} onChange={e => setFilter(e.target.value)} aria-label={`Find in ${label ?? "the table"}`} />}
			<table className="data-table" aria-label={label}>
				<thead>
					<tr>
						{columns.map(column => (
							<th key={column.key} aria-sort={sort?.key === column.key ? (sort.descending ? "descending" : "ascending") : undefined}>
								{column.sortBy ? (
									<button type="button" className="sort" onClick={() => sortOn(column.key)}>
										{column.label}
									</button>
								) : (
									column.label
								)}
							</th>
						))}
					</tr>
				</thead>
				<tbody>
					{shown.map(row => (
						<tr key={rowKey(row)} className={onRowClick ? "link" : undefined} onClick={onRowClick ? () => onRowClick(row) : undefined}>
							{columns.map(column => (
								<td key={column.key}>{column.render ? column.render(row) : String((row as Record<string, unknown>)[column.key] ?? "")}</td>
							))}
						</tr>
					))}
					{rows !== undefined && shown.length === 0 && (
						<tr>
							<td colSpan={columns.length} className="muted">
								{empty}
							</td>
						</tr>
					)}
				</tbody>
			</table>
			{paging && (paging.hasPrevious || paging.hasNext) && (
				<div className="form-actions table-paging">
					<button type="button" className="btn" disabled={!paging.hasPrevious} onClick={paging.previous}>
						Previous
					</button>
					{paging.number !== undefined && <span className="muted">Page {paging.number}</span>}
					<button type="button" className="btn" disabled={!paging.hasNext} onClick={paging.next}>
						Next
					</button>
				</div>
			)}
		</div>
	);
}
