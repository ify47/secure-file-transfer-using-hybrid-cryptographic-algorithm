"use client";
import Image from "next/image";
import { useState, useRef, useEffect } from "react";
import icon from "../assets/uniqueIcon.jpeg";
import Link from "next/link";
import { signOut } from "next-auth/react";

type ProfileDropDownProps = {
  class?: string;
};

// Profile Dropdown
const ProfileDropDown = (props: ProfileDropDownProps) => {
  const [state, setState] = useState(false);
  const profileRef = useRef<null | HTMLButtonElement>(null);

  const navigation = [
    { title: "Settings", path: "/dashboard/settings" },
    { title: "Log out", path: "#" },
  ];

  useEffect(() => {
    const handleDropDown = (e: any) => {
      if (!profileRef.current?.contains(e.target)) setState(false);
    };
    document.addEventListener("click", handleDropDown);
  }, []);

  return (
    <div className={`relative ${props.class}`}>
      <div className="flex items-center space-x-4">
        <button
          ref={profileRef}
          className="w-10 h-10 outline-none rounded-full ring-offset-2 ring-gray-200 ring-2 lg:focus:ring-indigo-600"
          onClick={() => setState(!state)}
        >
          <Image src={icon} className="w-full h-full rounded-full" alt="logo" />
        </button>
        <div className="lg:hidden">
          <span className="block">Micheal John</span>
          <span className="block text-sm text-gray-500">john@gmail.com</span>
        </div>
      </div>
      <ul
        className={`bg-white top-12 right-0 mt-5 space-y-5 lg:absolute lg:border lg:rounded-md lg:text-sm lg:w-52 lg:shadow-md lg:space-y-0 lg:mt-0 ${
          state ? "" : "lg:hidden"
        }`}
      >
        <li>
          <Link
            className="block text-gray-600 lg:hover:bg-gray-50 lg:p-2.5"
            href="/dashboard/settings"
          >
            Settings
          </Link>
        </li>
        <li>
          <Link
            onClick={() => signOut()}
            href="#"
            className="block text-gray-600 lg:hover:bg-gray-50 lg:p-2.5"
          >
            Log out
          </Link>
        </li>
      </ul>
    </div>
  );
};

export default function DashboardNav() {
  const [menuState, setMenuState] = useState(false);

  const navigation = [
    { title: "Dashboard(AES+RSA)", path: "/dashboard" },
    { title: "Dashboard(AES+ECC)", path: "/dashboard/dashboardEcc" },
    { title: "Recieved Files(AES+RSA)", path: "/dashboard/recieved-files" },
    { title: "Recieved Files(AES+ECC)", path: "/dashboard/recieved-filesEcc" },
  ];
  return (
    <nav className="bg-white border-b">
      <div className="flex items-center space-x-8 py-3 px-4 max-w-screen-xl mx-auto md:px-8">
        <div className="flex-1 flex items-center justify-between">
          <div
            className={`bg-white absolute z-20 w-full top-16 left-0 p-4 border-b lg:static lg:block lg:border-none ${
              menuState ? "" : "hidden"
            }`}
          >
            <ul className="mt-12 space-y-5 lg:flex lg:space-x-6 lg:space-y-0 lg:mt-0">
              {navigation.map((item, idx) => (
                <li key={idx} className="text-gray-600 hover:text-gray-900">
                  <Link onClick={() => setMenuState(false)} href={item.path}>
                    {item.title}
                  </Link>
                </li>
              ))}
            </ul>
            <ProfileDropDown class="mt-5 pt-5 border-t lg:hidden" />
          </div>
          <div className="flex-1 flex items-center justify-end space-x-2 sm:space-x-6">
            <ProfileDropDown class="hidden lg:block" />
            <button
              className="outline-none text-gray-400 block lg:hidden"
              onClick={() => setMenuState(!menuState)}
            >
              {menuState ? (
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-6 w-6"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              ) : (
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-6 w-6"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 6h16M4 12h16m-7 6h7"
                  />
                </svg>
              )}
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
