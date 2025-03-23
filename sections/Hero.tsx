"use client"
import { Card, CardContent } from "@/components/ui/card";
import {
  Carousel,
  CarouselContent,
  CarouselItem,
  CarouselNext,
  CarouselPrevious,
} from "@/components/ui/carousel";
import Image from "next/image";
import Autoplay from "embla-carousel-autoplay";

export default function Hero() {
  return (
    <div className="w-full">
      <Carousel className="w-full" plugins={[Autoplay({ delay: 3000 })]}>
        <CarouselContent>
          <CarouselItem className="w-full">
            <div className="mx-auto relative h-[500px] md:h-[85vh] w-full bg-[url('/assets/images/Landingpage/Banner2.svg')] bg-cover bg-center bg-no-repeat grid grid-cols-1 md:grid-cols-2">
              <div className="col-span-1 flex items-center justify-center px-4 md:px-0">
                <div className="flex flex-col gap-4 text-white">
                  <div className="text-sm bg-[#00A76F] text-white w-fit px-2 py-1 rounded">
                    20% OFF
                  </div>
                  <h1 className="text-3xl md:text-5xl font-bold">
                    BEST TOOLS FOR SALE
                  </h1>
                  <h2 className="text-4xl md:text-6xl font-bold bg-gradient-to-l from-[#FF2021] to-[#FF7F7E] bg-clip-text text-transparent">
                    MC PRECISION SUPER
                  </h2>
                  <p className="text-white max-w-md text-sm md:text-base">
                    Lorem Ipsum is simply dummy text of the printing and
                    typesetting industry. Lorem Ipsum has been the industry's
                    standard dummy text ever.
                  </p>
                  <button className="bg-[#B01116] text-white px-6 py-3 rounded w-fit hover:bg-red-800 text-sm md:text-base">
                    Shop Now
                  </button>
                </div>
              </div>
              <div className="hidden md:flex items-center justify-center">
                <Image
                  alt="Banner-sub-Image"
                  src={"/assets/images/Landingpage/Banner2_image.svg"}
                  className="w-[734px] h-[451px]"
                  width={734}
                  height={451}
                />
              </div>
            </div>
          </CarouselItem>
          <CarouselItem className="w-full">
            <div className="mx-auto relative h-[500px] md:h-[85vh]  w-full bg-[url('/assets/images/Landingpage/Banner1.jpg')] bg-cover bg-left md:bg-center bg-no-repeat grid grid-cols-1 md:grid-cols-2">
              <div className="col-span-1 flex items-center justify-center px-4 md:px-0 mt-0 md:mt-[-4.5rem]">
                <div className="flex flex-col gap-4 text-black">
                  <div className="text-sm bg-[#00A76F] text-white w-fit px-2 py-1 rounded">
                    20% OFF
                  </div>
                  <h1 className="text-3xl md:text-5xl font-bold">
                    BEST TOOLS FOR SALE
                  </h1>
                  <h2 className="text-4xl md:text-6xl font-bold bg-gradient-to-l from-transparent via-black to-transparent p-2 pl-0 px-[3rem] text-white">
                    MC PRECISION SUPER
                  </h2>
                  <p className="text-black max-w-md text-sm md:text-base">
                    Lorem Ipsum is simply dummy text of the printing and
                    typesetting industry. Lorem Ipsum has been the industry's
                    standard dummy text ever.
                  </p>
                  <button className="bg-gradient-to-b from-[#1177B0] to-[#1170FF] text-white px-6 py-3 rounded w-fit hover:bg-red-800 text-sm md:text-base">
                    Shop Now
                  </button>
                </div>
              </div>
            </div>
          </CarouselItem>
        </CarouselContent>
        {/* <CarouselPrevious className="hidden md:flex" />
        <CarouselNext className="hidden md:flex" /> */}
      </Carousel>
    </div>
  );
}
