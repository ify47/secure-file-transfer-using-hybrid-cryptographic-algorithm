import DashboardNav from "@/components/dashboadNav";
import React, { ReactNode } from "react";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <DashboardNav />
      {children}
    </>
  );
}
