import { NavLink } from 'react-router-dom'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '◫' },
  { path: '/upload', label: 'Upload APK', icon: '⬆' },
  { path: '/history', label: 'History', icon: '☰' },
]

export default function Sidebar() {
  return (
    <aside className="w-56 bg-sentinel-surface border-r border-sentinel-border flex flex-col shrink-0">
      {/* Logo */}
      <div className="h-14 flex items-center px-5 border-b border-sentinel-border">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 bg-sentinel-accent rounded flex items-center justify-center text-white text-xs font-bold">
            S
          </div>
          <div>
            <span className="text-sm font-semibold text-sentinel-text tracking-tight">
              APK Sentinel
            </span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-3 py-2 rounded text-sm transition-colors ${
                isActive
                  ? 'bg-sentinel-accent/10 text-sentinel-accent font-medium'
                  : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-hover'
              }`
            }
          >
            <span className="text-base w-5 text-center">{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-3 border-t border-sentinel-border">
        <p className="text-[10px] text-sentinel-muted leading-tight">
          Static Analysis Only
        </p>
        <p className="text-[10px] text-sentinel-muted leading-tight">
          v0.1.0
        </p>
      </div>
    </aside>
  )
}
