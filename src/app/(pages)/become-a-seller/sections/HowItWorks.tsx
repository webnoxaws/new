import Image from "next/image";
import React from "react";

function HowItWorks() {
  return (
    <div className="bg-white text-black py-8 px-4 md:px-8 mt-[7rem]">
      <div className="container mx-auto">
        <div className="flex items-center justify-center mb-8">
          <div className="h-px bg-gray-300 flex-grow"></div>
          <h2 className="text-[#b01116] text-2xl md:text-3xl font-bold px-4 py-[1rem]">
            How It Works
          </h2>
          <div className="h-px bg-gray-300 flex-grow"></div>
        </div>
        <div className="w-full h-[55vh] flex group">
          <div className="group/item p-[2rem] bg-[#90daf5] h-full flex-2 hover:flex-2 group-hover:flex-1  rounded-3xl m-2 transition-all duration-400 cursor-pointer flex  justify-around items-center hover:flex-row group-hover:flex-col">
            <Image
              src={"/assets/images/become-a-seller/listYourProducts.png"}
              width={312}
              height={394}
              className="w-[300px] h-[340px]"
              alt="listYourProducts"
            />
            <p className="font-[600] text-[20px]  text-start group-hover:text-start ">
              Register & List Your
              <br /> Products
            </p>
          </div>
          <div className="group/item p-[2rem] bg-[#ffbbe2] h-full flex-1 hover:flex-2 group-hover:flex-1  rounded-3xl m-2 transition-all duration-400 cursor-pointer flex  justify-around items-center flex-col hover:flex-row group-hover:flex-col">
            <Image
              src={"/assets/images/become-a-seller/GetOrders.png"}
              width={312}
              height={394}
              className="w-[350px] h-[340px]"
              alt="listYourProducts"
            />
            <p className="font-[600] text-[20px]  text-center group-hover/item:text-start ">
              Register & List Your
              <br /> Products
            </p>
          </div>
          <div className="group/item p-[2rem] bg-[#adaef5] h-full flex-1 hover:flex-2 group-hover:flex-1  rounded-3xl m-2 transition-all duration-400 cursor-pointer flex  justify-around items-center flex-col hover:flex-row group-hover:flex-col">
            <Image
              src={"/assets/images/become-a-seller/pay.png"}
              width={312}
              height={394}
              className="w-[300px] h-[340px]"
              alt="listYourProducts"
            />
            <p className="font-[600] text-[20px]  text-center group-hover/item:text-start">
              Register & List Your
              <br /> Products
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default HowItWorks;
