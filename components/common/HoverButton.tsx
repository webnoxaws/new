import React, { ReactNode } from "react";

function HoverButton({ children }: { children: ReactNode }) {
  return (
    <button className="cursor-pointer relative overflow-hidden px-4 py-2 text-white text-lg font-semibold rounded-[12px] bg-[#cc0000] border-1 border-transparent transition-all duration-400 ease-[cubic-bezier(0.4,0,0.2,1)] hover:bg-white hover:border-[#cc0000] hover:text-[#cc0000] hover:shadow-lg hover:shadow-[#cc0000/30%] before:content-[''] before:absolute before:top-1/2 before:left-1/2 before:w-[20px] before:h-[20px] before:bg-white/20 before:rounded-full before:-translate-x-1/2 before:-translate-y-1/2 before:scale-0 before:transition-all before:duration-500 before:ease-in-out hover:before:scale-[8] hover:before:bg-white/0 active:scale-95">
      <span className="relative z-20">{children}</span>
    </button>
  );
}

export default HoverButton;
