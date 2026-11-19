import React, { useState } from 'react';
import Sidebar from '../components/Sidebar';
import Navbar from '../components/Navbar';

const MainLayout = ({ currentPage, setCurrentPage, children }) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-cyber-950 flex">
      {/* Sidebar */}
      <Sidebar
        currentPage={currentPage}
        setCurrentPage={setCurrentPage}
        isOpen={isSidebarOpen}
        setIsOpen={setIsSidebarOpen}
      />

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        <Navbar
          currentPage={currentPage}
          setCurrentPage={setCurrentPage}
          setIsSidebarOpen={setIsSidebarOpen}
        />

        <main className="flex-1 p-4 lg:p-8 max-w-7xl w-full mx-auto">
          {children}
        </main>

        {/* Global Footer */}
        <footer className="border-t border-slate-800/60 py-4 px-6 text-center text-[11px] text-slate-500 font-mono">
          Email Privacy Analyzer (EPA) &bull; Enterprise Cyber Intelligence &bull; Heuristic Risk Scoring &bull; Presidio PII Engine
        </footer>
      </div>
    </div>
  );
};

export default MainLayout;
