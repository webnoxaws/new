"use client";

import { useState } from "react";
import ProductCard from "@/components/common/ProductCard";
import { cn } from "@/lib/utils";
import HoverButton from "@/components/common/HoverButton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const categories = [
  "New Arrival",
  "Best Selling",
  "Top rated",
];

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

];

export default function FeaturedProducts() {
  const [activeCategory, setActiveCategory] = useState(categories[0]);

  return (
    <div className="bg-white text-black py-8 px-4 md:px-8 my-[2rem] mb-0">
      <div className="container mx-auto">
        <div className="flex items-center justify-center mb-8">
          <div className="h-px bg-gray-300 flex-grow"></div>
          <h2 className="text-[#b01116] text-2xl md:text-3xl font-bold px-4 py-[2rem]">
            Shop by popular categories
          </h2>
          <div className="h-px bg-gray-300 flex-grow"></div>
        </div>

        <Tabs defaultValue={categories[0]}>
          <TabsList>
            {categories.map((category) => (
              <TabsTrigger key={category} value={category}>
                {category}
              </TabsTrigger>
            ))}
          </TabsList>

          {categories.map((category) => (
            <TabsContent key={category} value={category}>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6 mx-auto">
                {products.map((product, index) => (
                  <ProductCard
                    index={index+1}
                    key={product.id}
                    product={product}
                  />
                ))}
              </div>
            </TabsContent>
          ))}
        </Tabs>

        <div className="w-full my-[4rem] flex justify-center">
          <HoverButton>Show More</HoverButton>
        </div>
      </div>
    </div>
  );
}
