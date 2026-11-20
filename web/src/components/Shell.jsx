import { Outlet, NavLink } from "react-router-dom";

export default function Shell({ user }) {
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-brand">mcp-cve</div>
        <nav className="sidebar-nav">
          <NavLink to="/cves" className={({ isActive }) => "sidebar-link" + (isActive ? " active" : "")}>
            CVEs
          </NavLink>
          {user?.role === "admin" && (
            <NavLink to="/agents" className={({ isActive }) => "sidebar-link" + (isActive ? " active" : "")}>
              Agents
            </NavLink>
          )}
        </nav>
        {user && (
          <div className="sidebar-user">
            <span className="sidebar-user-name">{user.display_name}</span>
            <form method="post" action="/auth/logout">
              <button type="submit" className="sidebar-logout">Sign out</button>
            </form>
          </div>
        )}
      </aside>
      <div className="content-area">
        <Outlet />
      </div>
    </div>
  );
}
