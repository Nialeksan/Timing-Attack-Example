import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

export default function Dashboard() {
    const [user, setUser] = useState(null);
    const navigate = useNavigate();

    useEffect(() => {
        fetch(`${import.meta.env.VITE_API_URL}/auth/me`, {
            credentials: 'include',
        })
        .then(res => res.json())
        .then(data => setUser(data.user));
    }, []);

    async function handleLogout() {
        await fetch(`${import.meta.env.VITE_API_URL}/auth/logout`, {
            method: 'POST',
            credentials: 'include',
        });
        navigate('/login');
    }

    if (!user) return <p>Loading...</p>;

    return (
        <div className="page">
            <header className="dashboard-header">
                <h1>Welcome, {user.full_name}</h1>
                <button onClick={handleLogout}>Logout</button>
            </header>

            <main className="dashboard-main">
                <section className="card">
                    <h2>Personal information</h2>
                    <dl>
                        <dt>Email</dt>
                        <dd>{user.email}</dd>
                        <dt>Phone</dt>
                        <dd>{user.phone}</dd>
                        <dt>Date of birth</dt>
                        <dd>{new Date(user.date_of_birth).toLocaleDateString('en-MX')}</dd>
                    </dl>
                </section>

                <section className="card card--sensitive">
                    <h2>Government IDs</h2>
                    <p className="card__warning">
                        This information is sensitive. Never share it.
                    </p>
                    <dl>
                        <dt>CURP</dt>
                        <dd>{user.curp}</dd>
                        <dt>RFC</dt>
                        <dd>{user.rfc}</dd>
                        <dt>NSS</dt>
                        <dd>{user.nss}</dd>
                    </dl>
                </section>
            </main>
        </div>
    );
}