import { useState } from "react";
import {useNavigate, Link} from 'react-router-dom';

export default function Register() {
    const [form, setForm] = useState({
        email: '',
        password: '',
        full_name: '',
        date_of_birth: '',
        phone: '',
        curp: '',
        rfc: '',
        nss: '',
        security_question: '',
        security_answer: '',
    });
    const [error, setError] = useState('');
    const navigate = useNavigate();

    function handleChange(e) {
        setForm(prev => ({ ...prev, [e.target.name]: e.target.value}));
    }

    async function handleSubmit(e) {
        e.preventDefault();
        setError('');

        const res = await fetch(`${import.meta.env.VITE_API_URL}/auth/register`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify(form),
        });

        if (res.ok) {
            navigate('/dashboard');
        } else {
            const data = await res.json();
            setError(data.message ?? 'Registration failed');
        }
    }

    return (
        <div className="auth-page">
            <div className="auth-card">
                <h1 className="auth-title">PIA — Secure Portal</h1>
                <h2 className="auth-subtitle">Create account</h2>

                {error && <p className="form-error">{error}</p>}

                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label htmlFor="full_name">Full name</label>
                        <input id="full_name" name="full_name" type="text" 
                            value={form.full_name} onChange={handleChange} required />
                    </div>
                    <div className="form-group">
                        <label htmlFor="email">Email</label>
                        <input id="email" name="email" type="email" 
                            value={form.email} onChange={handleChange} required />
                    </div>
                    <div className="form-group">
                        <label htmlFor="password">Password</label>
                        <input id="password" name="password" type="password" 
                            value={form.password} onChange={handleChange} required />
                    </div>
                    <div className="form-group">
                        <label htmlFor="date_of_birth">Date of birth</label>
                        <input id="date_of_birth" name="date_of_birth" type="date" 
                            value={form.date_of_birth} onChange={handleChange} required />
                    </div>
                    <div className="form-group">
                        <label htmlFor="phone">Phone</label>
                        <input id="phone" name="phone" type="tel" 
                            value={form.phone} onChange={handleChange} required />
                    </div>
                    <div className="form-group">
                        <label htmlFor="curp">CURP</label>
                        <input id="curp" name="curp" type="text" 
                            value={form.curp} onChange={handleChange} required />
                    </div>
                    <div className="form-group">
                        <label htmlFor="rfc">RFC</label>
                        <input id="rfc" name="rfc" type="text" 
                            value={form.rfc} onChange={handleChange} required />
                    </div>
                    <div className="form-group">
                        <label htmlFor="nss">NSS</label>
                        <input id="nss" name="nss" type="text" 
                            value={form.nss} onChange={handleChange} required />
                    </div>
                    <div className="form-group">
                        {/* For this excercise, questions can be hardcoded into select */}
                        <label htmlFor="security_question">Security question</label>
                        <select name="security_question" id="security_question"
                            value={form.security_question} onChange={handleChange} required>
                            <option value="">Select a question</option>
                            <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                            <option value="What city were you born in?">What city were you born in?</option>
                            <option value="What was the title of your favorite movie growing up?">What was the title of your favorite movie growing up?</option>
                        </select>
                    </div>
                    <div className="form-group">
                        <label htmlFor="security_answer">Security answer</label>
                        <input id="security_answer" name="security_answer" type="text" 
                            value={form.security_answer} onChange={handleChange} required />
                    </div>

                    <button className="btn btn--primary" type="submit">Create account</button>
                </form>

                <p className="auth-links">Already have an account? <Link to="/login">Sign in</Link></p>
            </div>
        </div>
        
    );
}