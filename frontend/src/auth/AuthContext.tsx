import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, clearToken, getStoredBusinessId, getStoredUser, getToken, setStoredBusinessId, setStoredUser, setToken } from '../api/client';
import type { BusinessCreate, BusinessResponse, UserResponse } from '../types/backend';

interface AuthContextType {
  user: UserResponse | null;
  token: string | null;
  business: BusinessResponse | null;
  businesses: BusinessResponse[];
  businessId: number | null;
  loading: boolean;
  login: (token: string, user: UserResponse) => void;
  logout: () => void;
  selectBusiness: (businessId: number) => void;
  createBusiness: (payload: BusinessCreate) => Promise<BusinessResponse>;
  loadBusinesses: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [token, setTokenState] = useState<string | null>(null);
  const [business, setBusiness] = useState<BusinessResponse | null>(null);
  const [businesses, setBusinesses] = useState<BusinessResponse[]>([]);
  const [businessId, setBusinessId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const init = async () => {
      try {
        const storedToken = getToken();
        const storedUser = getStoredUser();
        const storedBusinessId = getStoredBusinessId();
        if (storedToken && storedUser) {
          setTokenState(storedToken);
          setUser(storedUser);
          setBusinessId(storedBusinessId);
          try {
            await loadBusinesses();
          } catch {
            // Business list may be temporarily inaccessible; onboarding handles recovery
          }
          if (storedBusinessId) {
            try {
              const biz = await api.get<BusinessResponse>(`/api/businesses/${storedBusinessId}`);
              if (mounted) setBusiness(biz);
            } catch {
              // Business may no longer be accessible; keep businessId but no business object
            }
          }
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };
    init();
    return () => { mounted = false; };
  }, []);

  const loadBusinesses = async (): Promise<void> => {
    const list = await api.get<BusinessResponse[]>('/api/businesses');
    setBusinesses(list);
  };

  const login = (accessToken: string, userData: UserResponse) => {
    setToken(accessToken);
    setTokenState(accessToken);
    setStoredUser(userData);
    setUser(userData);
  };

  const selectBusiness = async (id: number) => {
    setBusinessId(id);
    setStoredBusinessId(id);
    try {
      const biz = await api.get<BusinessResponse>(`/api/businesses/${id}`);
      setBusiness(biz);
    } catch {
      setBusiness(null);
    }
  };

  const createBusiness = async (payload: BusinessCreate): Promise<BusinessResponse> => {
    const biz = await api.post<BusinessResponse>('/api/businesses', payload);
    setBusinesses((prev) => [...prev, biz]);
    await selectBusiness(biz.id);
    return biz;
  };

  const logout = () => {
    clearToken();
    setTokenState(null);
    setUser(null);
    setBusiness(null);
    setBusinesses([]);
    setBusinessId(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, business, businesses, businessId, loading, login, logout, selectBusiness, createBusiness, loadBusinesses }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
