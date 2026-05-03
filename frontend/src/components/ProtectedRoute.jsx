import {useEffect, useState} from 'react';
import {Navigate } from 'react-router-dom';

export default function ProtectedRoute({children, requireAdmin=false}) {
    const [status, setStatus] = useState('loading'); // status starts at 'loading'. It can be 'ok' or 'unauthorized'
    const [user, setUser] = useState(null); // user starts at null. If session, fills with user data

    useEffect(() => {
        fetch(`${import.meta.env.VITE_API_URL}/auth/me`, {
            credentials: 'include',
        })
            .then(res => res.ok ? res.json() : Promise.reject(res.status))
            .then(data => {
                if (requireAdmin && data.user.role !== 'admin') {
                    setStatus('unauthorized');
                } else {
                    setUser(data.user);
                    setStatus('ok');
                }
            })
            .catch(() => setStatus('unauthorized'));
    }, [requireAdmin]); // requireAdmin as dependency array. If requireAdmin changes, effect needs to re-evaluate.

    if (status === 'loading') return null;
    if (status === 'unauthorized') return <Navigate to="/login" replace/>;
    return children;
}