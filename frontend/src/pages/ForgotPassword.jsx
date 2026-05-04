import { useState } from "react";
import { Link } from "react-router-dom";

export default function ForgotPassword() {
    const [step, setStep] = useState(1);
    const [secure, setSecure] = useState(false);
    const [email, setEmail] = useState('');
    const [resetToken, setResetToken] = useState('');
    const [securityQuestion, setSecurityQuestion] = useState('');
    const [answer, setAnswer] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [error, setError] = useState('');
    const [done, setDone] = useState(false);

    async function handleStep1(e) {
        e.preventDefault();
        setError('');

        const endpoint = secure ? '/auth/forgot-password-secure' : '/auth/forgot-password';
        const res = await fetch(`${import.meta.env.VITE_API_URL}${endpoint}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email}),
        });

        if (res.ok) {
            const data = await res.json();
            setResetToken(data.reset_token);
            setSecurityQuestion(data.security_question);
            setStep(2);
        } else {
            const data = await res.json();
            setError(data.message ?? 'Error');
        }
    }

    async function handleStep2(e) {
        e.preventDefault();
        setError('');

        const endpoint = secure ? '/auth/forgot-password-secure/answer' : '/auth/forgot-password/answer';
        const res = await fetch(`${import.meta.env.VITE_API_URL}${endpoint}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({reset_token: resetToken, answer}),
        });

        if (res.ok) {
            setStep(3);
        } else {
            const data = await res.json();
            setError(data.message ?? 'Error');
        }
    }

    async function handleStep3(e) {
        e.preventDefault();
        setError('');

        const endpoint = secure ? '/auth/forgot-password-secure/reset' : '/auth/forgot-password/reset';
        const res = await fetch(`${import.meta.env.VITE_API_URL}${endpoint}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({reset_token: resetToken, new_password: newPassword}),
        });

        if (res.ok) {
            setDone(true);
        } else {
            const data = await res.json();
            setError(data.message ?? 'Error');
        }
    }

    if (done) {
        return (
            <div className="auth-page">
                <div className="auth-card">
                    <h2 className="auth-subtitle">Password reset successfully</h2>
                    <p className="auth-links"><Link to="/login">Back to sign in</Link></p>
                </div>
            </div>
        );
    }

    return (
        <div className="auth-page">
            <div className="auth-card">
                <h1 className="auth-title">PIA — Secure Portal</h1>
                <h2 className="auth-subtitle">Reset password</h2>

                {error && <p className="form-error">{error}</p>}

                <div className="toggle-wrapper">
                    <span className="toggle-label">
                        {secure ? '🔒 Secure' : '🔓 Vulnerable'}
                    </span>
                    <label className="toggle-switch" htmlFor="secureToggle">
                        <input 
                            id="secureToggle"
                            type="checkbox"
                            checked={secure}
                            onChange={() => setSecure(s => !s)} 
                        />
                        <span className="toggle-slider"></span>
                    </label>
                </div>

                {step === 1 && (
                    <form className="auth-form" onSubmit={handleStep1}>
                        <div className="form-group">
                            <label htmlFor="email">Email</label>
                            <input id="email" type="email"
                                value={email} onChange={e => setEmail(e.target.value)} required />
                        </div>
                        <button className="btn btn--primary" type="submit">Continue</button>
                    </form>
                )}

                {step === 2 && (
                    <form className="auth-form" onSubmit={handleStep2}>
                        <p className="security-question">{securityQuestion}</p>
                        <div className="form-group">
                            <label htmlFor="answer">Your answer</label>
                            <input id="answer" type="text"
                                value={answer} onChange={e => setAnswer(e.target.value)} required />
                        </div>
                        <button className="btn btn--primary" type="submit">Verify</button>
                    </form>
                )}

                {step === 3 && (
                    <form className="auth-form" onSubmit={handleStep3}>
                        <div className="form-group">
                            <label htmlFor="newPassword">New Password</label>
                            <input id="newPassword" type="password"
                                value={newPassword} onChange={e => setNewPassword(e.target.value)} required />
                        </div>
                        <button className="btn btn--primary" type="submit">Reset Password</button>
                    </form>
                )}

                <p className="auth-links"><Link to="/login">Back to sign in</Link></p>
            </div>
        </div>
    );
}