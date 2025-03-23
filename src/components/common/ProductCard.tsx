"use client"

import { useState } from "react"
import { Heart, Share2, ShoppingCart } from "lucide-react"
import { cn } from "@/lib/utils"
import { motion, AnimatePresence } from "framer-motion"
import Image from "next/image"

interface ProductCardProps {
  product: {
    id: number
    name: string
    description: string
    price: number
    originalPrice?: number
    image: string
    badge?: string
  },
  index: number,
  className?: string
}

export default function ProductCard({ product, index,className }: ProductCardProps) {
  const [isHovered, setIsHovered] = useState(false)

  const buttonVariants = {
    hidden: { x: 50, opacity: 0 },
    visible: (i: number) => ({
      x: 0,
      opacity: 1,
      transition: {
        delay: i * 0.1,
        duration: 0.3,
        ease: "easeOut"
      }
    }),
    exit: (i: number) => ({
      x: 50,
      opacity: 0,
      transition: {
        delay: i * 0.05,
        duration: 0.2,
        ease: "easeIn"
      }
    })
  }

  return (
    <div
      className={cn(
        "bg-white rounded-lg overflow-hidden transition-all duration-300 relative shadow-[0px_0px_18.26px_0px_#00000014] cursor-pointer",
        (index == 0 ? "col-span-0 md:col-span-2" : ""),
        isHovered ? "shadow-[-2px_3px_17px_6px_#ffcfd0]" : "",
        className
      )}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {product.badge && (
        <div
          className={cn(
            "absolute top-6 left-0 px-3 py-1 text-white text-sm font-medium",
            product.badge === "Hot Sale" ? "bg-red-500" : "bg-green-500",
          )}
        >
          {product.badge}
        </div>
      )}

      <div className="p-4 flex justify-center">
        <Image
          src={product.image} 
          alt={product.name} 
          width={160}
          height={160}
          className="h-40 w-auto object-contain" 
        />
      </div>

      <div className="p-4">
        <h3 className="text-lg font-bold text-gray-900">{product.name}</h3>
        <p className="text-gray-500">{product.description}</p>
        <div className="mt-2 flex items-center">
          <span className="text-red-600 font-bold text-lg">₹{product.price}</span>
          {product.originalPrice && <span className="ml-2 text-gray-400 line-through">₹{product.originalPrice}</span>}
        </div>
      </div>

      <AnimatePresence>
        {isHovered && (
          <div className="absolute right-[1.5rem] top-1/3 transform -translate-y-1/2 flex flex-col gap-2">
            <motion.button
              variants={buttonVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
              custom={0}
              className="bg-red-600 text-white p-2 rounded-full hover:bg-red-700 transition-colors"
            >
              <Heart size={18} />
            </motion.button>
            <motion.button
              variants={buttonVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
              custom={1}
              className="bg-red-600 text-white p-2 rounded-full hover:bg-red-700 transition-colors"
            >
              <ShoppingCart size={18} />
            </motion.button>
            <motion.button
              variants={buttonVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
              custom={2}
              className="bg-red-600 text-white p-2 rounded-full hover:bg-red-700 transition-colors"
            >
              <Share2 size={18} />
            </motion.button>
          </div>
        )}
      </AnimatePresence>
    </div>
  )
}

