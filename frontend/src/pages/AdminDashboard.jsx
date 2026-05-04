import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

export default function AdminDashboard() {
    const [users, setUsers] = useState([]);
    const navigate = useNavigate();

    useEffect(() => {
        fetch(`${import.meta.env.VITE_API_URL}/admin/users`, {
            credentials: 'include',
        })
        .then(res => res.json())
        .then(data => setUsers(data));
    }, []);

    async function handleLogout() {
        await fetch(`${import.meta.env.VITE_API_URL}/auth/logout`, {
            method: 'POST',
            credentials: 'include',
        });
        navigate('/login');
    }

    if (users.length === 0) return <p>Loading...</p>;

    return (
        <div className="page">
            <header className="dashboard-header">
                <h1>Admin Dashboard</h1>
                <button onClick={handleLogout}>Logout</button>
            </header>

            <main className="admin-main">
                <h2>Registered users ({users.length})</h2>

                <div className="table-wrapper">
                    <table className="users-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Phone</th>
                                <th>Date of birth</th>
                                <th>CURP</th>
                                <th>RFC</th>
                                <th>NSS</th>
                                <th>Registered</th>
                            </tr>
                        </thead>
                        <tbody>
                            {users.map(user => (
                                <tr key={user.id}>
                                    <td>{user.full_name}</td>
                                    <td>{user.email}</td>
                                    <td>
                                        <span className={`badge badge--${user.role}`}>
                                            {user.role}
                                        </span>
                                    </td>
                                    <td>{user.phone}</td>
                                    <td>{new Date(user.date_of_birth).toLocaleDateString('en-MX')}</td>
                                    <td className="cell--mono">{user.curp}</td>
                                    <td className="cell--mono">{user.rfc}</td>
                                    <td className="cell--mono">{user.nss}</td>
                                    <td>{new Date(user.created_at).toLocaleDateString('en-MX')}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </main>
        </div>
    );
}