import Link from "next/link";
import {
  MapPin,
  Phone,
  Smartphone,
  Truck,
  Award,
  RotateCcw,
  Headphones,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import Image from "next/image";

export default function Footer() {
  return (
    <footer className="w-full mt-[7rem] ">

      <div className="bg-[linear-gradient(175.63deg,#B80000_-2.16%,#310000_108.15%)] text-white py-12 relative">
        <div className="bg-white py-8 border-t border-b mx-auto w-[90%] mt-[-7rem] mb-[2rem] text-black shadow-[0px_0px_13.1px_0px_rgba(0,0,0,0.15)] rounded-lg">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 divide-y md:divide-y-0 md:divide-x divide-gray-200 ">
              <div className="flex items-center justify-center  p-4">
                <div className="mr-4">
                  <Truck className="h-10 w-10 text-[#b01116]" />
                </div>
                <div>
                  <h3 className="font-bold text-lg mb-1">Free home delivery</h3>
                  <p className="text-sm text-gray-600">
                    Lorem Ipsum is simply dummy text of the printing and
                    typesetting industry.
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-center  p-4">
                <div className="mr-4">
                  <Award className="h-10 w-10 text-[#b01116]" />
                </div>
                <div>
                  <h3 className="font-bold text-lg mb-1">Quality Products</h3>
                  <p className="text-sm text-gray-600">
                    Lorem Ipsum is simply dummy text of the printing and
                    typesetting industry.
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-center  p-4">
                <div className="mr-4">
                  <RotateCcw className="h-10 w-10 text-[#b01116]" />
                </div>
                <div>
                  <h3 className="font-bold text-lg mb-1">3 Days Return</h3>
                  <p className="text-sm text-gray-600">
                    Lorem Ipsum is simply dummy text of the printing and
                    typesetting industry.
                  </p>
                </div>
              </div>

              <div className="flex items-center p-4">
                <div className="mr-4">
                  <Image src={"/assets/icons/onlineSupport.svg"} width={70} height={70} alt="onlineSupport-icon"/>
                </div>
                <div>
                  <h3 className="font-bold text-lg mb-1">Online support</h3>
                  <p className="text-sm text-gray-600">
                    Lorem Ipsum is simply dummy text of the printing and
                    typesetting industry.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            <div>
              <div className="mb-6">
                <Link href="/" className="flex items-center">
                  <Link href="/" className="flex items-center">
                    <Image
                      src={"/assets/logo-white.svg"}
                      width={236}
                      height={64}
                      alt="Make-Easy-logo"
                    />
                  </Link>
                </Link>
              </div>

              <div className="space-y-3">
                <div className="flex items-start gap-2">
                  <MapPin className="h-5 w-5 mt-0.5 flex-shrink-0" />
                  <p className="text-sm">
                    16 A, Gandhi Street, 3rd Street, Ganapathy, Coimbatore - 641
                    006.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <Phone className="h-5 w-5 flex-shrink-0" />
                  <p className="text-sm">+ 91-422-4364187</p>
                </div>

                <div className="flex items-center gap-2">
                  <Smartphone className="h-5 w-5 flex-shrink-0" />
                  <p className="text-sm">+ 91-9894646837</p>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-xl font-bold mb-4">Company</h3>
              <ul className="space-y-3">
                <li>
                  <Link href="/about" className="text-sm hover:underline">
                    About
                  </Link>
                </li>
                <li>
                  <Link href="/blog" className="text-sm hover:underline">
                    Blog
                  </Link>
                </li>
                <li>
                  <Link href="/products" className="text-sm hover:underline">
                    All Products
                  </Link>
                </li>
                <li>
                  <Link href="/faq" className="text-sm hover:underline">
                    FAQ
                  </Link>
                </li>
              </ul>
            </div>

            <div>
              <h3 className="text-xl font-bold mb-4">Services</h3>
              <ul className="space-y-3">
                <li>
                  <Link
                    href="/order-tracking"
                    className="text-sm hover:underline"
                  >
                    Order tracking
                  </Link>
                </li>
                <li>
                  <Link href="/wishlist" className="text-sm hover:underline">
                    Wish List
                  </Link>
                </li>
                <li>
                  <Link href="/login" className="text-sm hover:underline">
                    Login
                  </Link>
                </li>
                <li>
                  <Link href="/account" className="text-sm hover:underline">
                    My Account
                  </Link>
                </li>
                <li>
                  <Link href="/terms" className="text-sm hover:underline">
                    Terms and conditions
                  </Link>
                </li>
              </ul>
            </div>

            <div>
              <h3 className="text-xl font-bold mb-4">Customer Care</h3>
              <ul className="space-y-3">
                <li>
                  <Link href="/login" className="text-sm hover:underline">
                    Login
                  </Link>
                </li>
                <li>
                  <Link href="/account" className="text-sm hover:underline">
                    My Account
                  </Link>
                </li>
                <li>
                  <Link href="/wishlist" className="text-sm hover:underline">
                    Wish List
                  </Link>
                </li>
                <li>
                  <Link
                    href="/order-tracking"
                    className="text-sm hover:underline"
                  >
                    Order Tracking
                  </Link>
                </li>
                <li>
                  <Link href="/contact" className="text-sm hover:underline">
                    Contact us
                  </Link>
                </li>
              </ul>
            </div>
          </div>

          <div className="mt-12">
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
              <div className="lg:col-span-2">
                <h3 className="text-xl font-bold mb-4">Newsletter</h3>
                <p className="text-sm mb-4">
                  Subscribe to our weekly updates and notifications
                </p>

                <div className="flex h-[3rem]">
                  <Input
                    type="email"
                    placeholder="Enter your email"
                    className="h-full rounded-sm bg-white text-black border-0 focus-visible:ring-0 focus-visible:ring-offset-0"
                  />
                  <Button className=" ml-2  rounded-sm h-full bg-black hover:bg-gray-800">
                    Send
                  </Button>
                </div>
              </div>

              <div className="lg:col-span-2 flex items-end justify-start lg:justify-end">
                <div className="flex gap-4">
                  <Link
                    href="#"
                    className="bg-white/10 p-2 rounded-md hover:bg-white/20"
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      width="24"
                      height="24"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M22 4s-.7 2.1-2 3.4c1.6 10-9.4 17.3-18 11.6 2.2.1 4.4-.6 6-2C3 15.5.5 9.6 3 5c2.2 2.6 5.6 4.1 9 4-.9-4.2 4-6.6 7-3.8 1.1 0 3-1.2 3-1.2z"></path>
                    </svg>
                  </Link>
                  <Link
                    href="#"
                    className="bg-white/10 p-2 rounded-md hover:bg-white/20"
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      width="24"
                      height="24"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <rect
                        width="20"
                        height="20"
                        x="2"
                        y="2"
                        rx="5"
                        ry="5"
                      ></rect>
                      <path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"></path>
                      <line x1="17.5" x2="17.51" y1="6.5" y2="6.5"></line>
                    </svg>
                  </Link>
                  <Link
                    href="#"
                    className="bg-white/10 p-2 rounded-md hover:bg-white/20"
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      width="24"
                      height="24"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M22.54 6.42a2.78 2.78 0 0 0-1.94-2C18.88 4 12 4 12 4s-6.88 0-8.6.46a2.78 2.78 0 0 0-1.94 2A29 29 0 0 0 1 11.75a29 29 0 0 0 .46 5.33A2.78 2.78 0 0 0 3.4 19c1.72.46 8.6.46 8.6.46s6.88 0 8.6-.46a2.78 2.78 0 0 0 1.94-2 29 29 0 0 0 .46-5.25 29 29 0 0 0-.46-5.33z"></path>
                      <polygon points="9.75 15.02 15.5 11.75 9.75 8.48 9.75 15.02"></polygon>
                    </svg>
                  </Link>
                  <Link
                    href="#"
                    className="bg-white/10 p-2 rounded-md hover:bg-white/20"
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      width="24"
                      height="24"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"></path>
                      <rect width="4" height="12" x="2" y="9"></rect>
                      <circle cx="4" cy="4" r="2"></circle>
                    </svg>
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
