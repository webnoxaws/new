import { AspectRatio } from "@/components/ui/aspect-ratio";
import FeaturedProducts from "./sections/FeaturedProducts";
import Hero from "./sections/Hero";
import Image from "next/image";
import ShopByPopularCategory from "./sections/ShopByPopularCategory";
import SpecialOffers from "./sections/SpecialOffers";

export default function Home() {
  return (
    <div className="w-full">
      <Hero />
      <ShopByPopularCategory />
      <div className="w-full">
        <Image
          src="/assets/images/Landingpage/Banner3.png"
          alt="Image"
          className=" object-cover w-full"
          width={1920}
          height={1080}
        />
      </div>
      <FeaturedProducts />
      <div className="w-full mb-[3rem] relative">
        <div
          className="relative w-full h-[500px] md:h-[600px] bg-cover bg-center"
          style={{
            backgroundImage: "url('/assets/images/Landingpage/Banner4.png')",
            backgroundSize: "cover",
            backgroundPosition: "center",
          }}
        >
          <div
            className="absolute top-0 left-0 w-full h-full"
            style={{
              background:
                "linear-gradient(181.86deg, #000000 6.27%, rgba(47, 47, 47, 0.8) 98.58%)",
            }}
          ></div>
          <div className="absolute top-0 left-0 w-full h-full grid grid-cols-1 md:grid-cols-2">
            <div className="flex items-center justify-center px-4 md:px-0">
              <div className="flex flex-col gap-4 text-white">
                <Image
                  alt="Banner-sub-Image"
                  src={"/assets/images/Landingpage/ews_logo.png"}
                  width={141}
                  height={48}
                  className="w-[100px] md:w-[141px]"
                />
                <div className="text-xs md:text-sm text-white w-fit px-2 rounded mt-[-1rem]">
                  Tool Technologies
                </div>
                <h1 className="text-2xl md:text-3xl lg:text-5xl font-bold">
                  ZERO-ZERO ADJUSTMENT <br className="hidden md:block" /> NUT ER 25
                </h1>

                <p className="text-white max-w-md text-xs md:text-sm lg:text-base">
                  Lorem Ipsum is simply dummy text of the printing and typesetting
                  industry. Lorem Ipsum has been the industry's standard dummy
                  text ever.
                </p>
                <button className="bg-white text-[#0061AB] px-4 md:px-5 py-2 md:py-3 rounded-xl w-fit cursor-pointer hover:bg-[#0061AB] hover:text-white text-xs md:text-sm lg:text-base transition duration-500 ease-in-out">
                  Shop Now
                </button>
              </div>
            </div>
            <div className="hidden md:flex items-center justify-center">
              <Image
                alt="Banner-sub-Image"
                src={"/assets/images/Landingpage/Banner4_image.svg"}
                className="w-auto h-[75%]"
                width={734}
                height={451}
              />
            </div>
          </div>
        </div>
      </div>
      <SpecialOffers />
    </div>
  );
}
