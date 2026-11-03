import { Search } from "lucide-react";

export default function SearchBox({ value, onChange, placeholder, variant = "white" }) {
  return (
    <div className={`search-shell ${variant}`}>
      <Search size={20} color="#8e8e93" strokeWidth={2} />
      <input
        className="search-input"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}
