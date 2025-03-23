"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Search,
  ChevronDown,
  User,
  ShoppingCart,
  Globe,
  Package,
  HelpCircle,
  Heart,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import Image from "next/image";
import { signOut, useSession } from "next-auth/react";

export default function Header() {
  const [searchQuery, setSearchQuery] = useState("");

  const { data, status } = useSession();

  console.log(data, status);

  return (
    <header className="w-full sticky top-0 left-0 z-[99] bg-white">
      <div className="w-full bg-[#b01116] text-white py-4">
        <div className="container mx-auto flex justify-end items-center gap-6 px-4">
          <button className="flex items-center gap-1 text-sm hover:text-gray-200">
            <Globe className="h-4 w-4" />
            English
          </button>
          <button className="flex items-center gap-1 text-sm hover:text-gray-200">
            <Package className="h-4 w-4" />
            Track your order
          </button>
          <button className="flex items-center gap-1 text-sm hover:text-gray-200">
            <HelpCircle className="h-4 w-4" />
            Helpcentre
          </button>
          <button className="flex items-center gap-1 text-sm hover:text-gray-200">
            <Heart className="h-4 w-4" />
            Wishlist
          </button>
        </div>
      </div>

      <div className=" border-b">
        <div className="container mx-auto py-4 flex items-center justify-between px-4">
          {/* Logo */}
          <Link href="/" className="flex items-center">
            <Image
              src={"/assets/logo.svg"}
              width={236}
              height={64}
              alt="Make-Easy-logo"
            />
          </Link>

          <div className="flex-1 max-w-xl mx-4 relative">
            <div className="flex ">
              <div className="relative flex-1">
                <Input
                  type="text"
                  placeholder="Search for products"
                  className="w-full pl-10 pr-4 py-6 rounded-l-full border-r-0 "
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              </div>
              <Button className="rounded-r-full bg-[#b01116] hover:bg-red-800 flex items-center gap-2 px-4 py-6">
                All Category
                <ChevronDown className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="flex items-center gap-6">
            {status === "authenticated" ? (
              <div
                onClick={() => {
                  signOut({ callbackUrl: "/" });
                }}
                className="flex items-center gap-2 hover:text-[#b01116] cursor-pointer"
              >
                {data.user?.image ? (
                  <Image
                    src={data.user?.image}
                    width={30}
                    height={30}
                    alt="user-icon"
                    className="rounded-full"
                  />
                ) : (
                  <Image
                    src={"/assets/icons/user.png"}
                    width={20}
                    height={20}
                    alt="user-icon"
                  />
                )}
                <div className="flex flex-col">
                  <span className="text-sm font-medium">{data.user?.name}</span>
                  <span className="text-xs text-gray-500">{data.user?.email}</span>
                </div>
              </div>
            ) : (
              <Link
                href="/auth/signin"
                className="flex items-center gap-2 hover:text-[#b01116]"
              >
                <Image
                  src={"/assets/icons/user.png"}
                  width={20}
                  height={20}
                  alt="user-icon"
                />
                <span>Account</span>
              </Link>
            )}
            <Link
              href="/cart"
              className="flex items-center gap-2 hover:text-[#b01116]"
            >
              <Image
                src={"/assets/icons/cart.svg"}
                width={20}
                height={20}
                alt="user-icon"
              />
              <span>cart</span>
            </Link>
            <Link
              href="/become-a-seller"
              className="flex items-center gap-2 hover:text-[#b01116]"
            >
              <div className="flex items-center gap-2">
                <Image
                  src={"/assets/icons/seller-store.svg"}
                  width={20}
                  height={20}
                  alt="seller-store"
                />
                <span>Become a seller</span>
              </div>
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}
