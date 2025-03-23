"use client"
import ProductCard from "@/components/common/ProductCard";
import { Carousel, CarouselContent, CarouselItem, CarouselNext, CarouselPrevious } from "@/components/ui/carousel";
import Autoplay from "embla-carousel-autoplay";
import Image from "next/image";
import React, { useCallback, useEffect, useState } from "react";
import { type CarouselApi } from "@/components/ui/carousel";
import TestimonialCard from "@/components/common/TestimonialCard";

function Testimonial() {
    const [api, setApi] = useState<CarouselApi>();
    const [activeIndex, setActiveIndex] = useState(0);

    useEffect(() => {
      if (!api) return;

      const onSelect = () => {
        setActiveIndex(api.selectedScrollSnap());
      };

      api.on("select", onSelect);
      api.on("reInit", onSelect);

      return () => {
        api.off("select", onSelect);
        api.off("reInit", onSelect);
      };
    }, [api]);

    const products = [
        {
          id: 1,
          name: "MC Precision",
          description: "Priming Pump",
          price: 1300,
          originalPrice: 1800,
          image: "/assets/images/item.png",
          badge: "Hot Sale",
        },
        {
          id: 2,
          name: "MC Precision",
          description: "Priming Pump",
          price: 1300,
          image: "/assets/images/item.png",
          badge: "New",
        },
        {
          id: 3,
          name: "MC Precision",
          description: "Priming Pump",
          price: 1300,
          image: "/assets/images/item.png",
          badge: "New",
        },
        {
          id: 4,
          name: "MC Precision",
          description: "Priming Pump",
          price: 1300,
          image: "/assets/images/item.png",
          badge: "New",
        },
        {
          id: 32,
          name: "MC Precision",
          description: "Priming Pump",
          price: 1300,
          image: "/assets/images/item.png",
          badge: "New",
        },
        {
          id: 43,
          name: "MC Precision",
          description: "Priming Pump",
          price: 1300,
          image: "/assets/images/item.png",
          badge: "New",
        },
      ];
      

  return (
    <div className="bg-white text-black  px-4 md:px-8 mt-[4rem]">
      <div className="container mx-auto">
        <div className="flex items-center justify-center mb-8">
          <div className="h-px bg-gray-300 flex-grow"></div>
          <h2 className="text-[#b01116] text-2xl md:text-3xl font-bold px-4 py-[1rem]">
            Testimonial
          </h2>
          <div className="h-px bg-gray-300 flex-grow"></div>
        </div>
        <div className="w-full h-[55vh] flex px-[2rem]">
          <Carousel
            plugins={[Autoplay({ delay: 2000 })]}
            opts={{
              align: "center",
              loop: true,
              skipSnaps: false,
              dragFree: false
            }}
            setApi={setApi}
            className="w-full"
          >
            <CarouselContent className="-ml-2 ">
              {products.map((product, index) => (
                <CarouselItem
                  key={product.id}
                  className="pl-2 md:basis-1/2 lg:basis-1/3 transition-transform duration-500 ease-out py-4"
                >
                  <div 
                    className={`transition-all duration-500 ease-out transform ${
                      activeIndex === index 
                        ? 'scale-110 z-10' 
                        : 'scale-90 opacity-70 blur-[0.5px]'
                    }`}
                  >
                    <TestimonialCard />
                  </div>
                </CarouselItem>
              ))}
            </CarouselContent>
            {/* <CarouselPrevious className="border-gray-600" />
            <CarouselNext className="border-gray-600" /> */}
          </Carousel>
        </div>
      </div>
    </div>
  );
}

export default Testimonial;
