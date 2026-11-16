import { Link } from "react-router";

export default function NotFound() {
	return (
		<div className="page">
			<div className="page-header">
				<h2>Not here</h2>
			</div>
			<p className="muted">
				There is no such page. <Link to="/">Your account</Link>
			</p>
		</div>
	);
}
