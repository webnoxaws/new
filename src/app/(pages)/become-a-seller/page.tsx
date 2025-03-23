import React from "react";
import Hero from "./sections/Hero";
import HowItWorks from "./sections/HowItWorks";
import Testimonial from "./sections/Testimonial";
import SellerRegistration from "./sections/SellerRegistration";

function Page() {
  return (
    <div className="w-full">
      <Hero />
      <HowItWorks />
      <Testimonial />
      <div className="w-full flex justify-center items-center">
        <SellerRegistration />
      </div>
    </div>
  );
}

export default Page;
