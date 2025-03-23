"use client";

import { useState } from "react";
import ProductCard from "@/components/common/ProductCard";
import { cn } from "@/lib/utils";
import HoverButton from "@/components/common/HoverButton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Carousel,
  CarouselContent,
  CarouselItem,
  CarouselNext,
  CarouselPrevious,
} from "@/components/ui/carousel";
import Autoplay from "embla-carousel-autoplay"

const categories = ["New Arrival", "Best Selling", "Top rated"];

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

export default function SpecialOffers() {
  const [activeCategory, setActiveCategory] = useState(categories[0]);

  return (
    <div className="bg-white text-black py-8 px-4 md:px-8 my-[2rem]">
      <div className="container mx-auto">
        <div className="flex items-center justify-center mb-8">
          <div className="h-px bg-gray-300 flex-grow"></div>
          <h2 className="text-[#b01116] text-2xl md:text-3xl font-bold px-4 py-[2rem]">
            Special Offers
          </h2>
          <div className="h-px bg-gray-300 flex-grow"></div>
        </div>

        <div className="w-full  px-[2rem]">
          <Carousel
            plugins={[
              Autoplay({delay:2000})
            ]}
            opts={{
              align: "start",
              loop:true,
              
            }}
            className="w-full"
          >
            <CarouselContent className="py-4">
              {products.map((product, index) => (
                <CarouselItem key={product.id} className="md:basis-1/2 lg:basis-1/4">
                  <ProductCard
                    index={index + 1}
                    key={product.id} 
                    product={product}
                  />
                </CarouselItem>
              ))}
            </CarouselContent>
            <CarouselPrevious className="border-gray-600" />
            <CarouselNext className="border-gray-600"  />
          </Carousel>
        </div>
      </div>
    </div>
  );
}
