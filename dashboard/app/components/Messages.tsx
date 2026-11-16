// What a screen says after a change: the error, or what was done.
export default function Messages({ error, message, loadError }: { error?: string; message?: string; loadError?: string }) {
	return (
		<>
			{loadError && <p className="form-error">{loadError}</p>}
			{error && (
				<p className="form-error" role="alert">
					{error}
				</p>
			)}
			{message && <p className="form-saved">{message}</p>}
		</>
	);
}
