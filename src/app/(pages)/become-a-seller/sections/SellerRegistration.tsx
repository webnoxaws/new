"use client";

import type React from "react";
import { z } from "zod";
import { useEffect, useState, type ChangeEvent } from "react";
import { motion } from "framer-motion";
import { Check, ArrowRight } from "lucide-react";
import Link from "next/link";
import Image from "next/image";
import {
  StepperForm,
  Tabs,
  Tab,
  TabContent,
  FormField,
  Actions,
  type StepperFormState,
  useStepperForm,
} from "@/components/common/stepper-form";
import { CustomInput } from "@/components/common/stepper-form/form-input";
import { useSellerRegistrationStore } from "@/store/sellerRegistrationStore";
import { SignInForm } from "../../auth/signin/page";
import { useSession } from "next-auth/react";

const isLoginedSchema = z.object({
  loginStatus: z.boolean().refine((val) => val === true, {
    message: "You must Login or Create a New Account",
  }),
});

const accountInfoSchema = z.object({
  fullName: z.string().min(2, "Full name must be at least 2 characters"),
  email: z.string().email("Please enter a valid email address"),
  gstn: z.string().min(15, "GSTN must be 15 characters"),
  storeName: z.string().min(2, "Store name must be at least 2 characters"),
  storeDescription: z.string().optional(),
  agreeTerms: z.boolean().refine((val) => val === true, {
    message: "You must agree to the terms and conditions",
  }),
});

const bankDetailsSchema = z.object({
  accountHolderName: z
    .string()
    .min(2, "Account holder name must be at least 2 characters"),
  accountNumber: z
    .string()
    .min(9, "Account number must be at least 9 characters"),
  bankName: z.string().min(2, "Bank name must be at least 2 characters"),
  ifscCode: z.string().min(11, "IFSC code must be 11 characters"),
  branchName: z.string().optional(),
  accountType: z.string().optional(),
  upiId: z.string().optional(),
});

const basePasswordSchema = z.object({
  password: z.string().min(8, "Password must be at least 8 characters"),
  confirmPassword: z.string(),
});

const passwordSchema = z
  .object({
    password: z.string().min(8, "Password must be at least 8 characters"),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });

const formSchema = z.object({
  ...accountInfoSchema.shape,
  ...bankDetailsSchema.shape,
  ...basePasswordSchema.shape,
});

const tabSchemas = [
  isLoginedSchema,
  accountInfoSchema,
  bankDetailsSchema,
  passwordSchema,
];

export default function SellerRegistration() {
  const {
    formState,
    isSubmitted,
    currentTab,
    setFormState,
    onFormChange,
    setIsSubmitted,
    setCurrentTab,
    resetForm,
  } = useSellerRegistrationStore();

  const { data, status, update } = useSession();

  console.log(data);
  console.log("formState  : ",formState[1].fields["fullName"]);

  const handleSubmit = (data: any) => {
    console.log("Form submitted:", data);
    setIsSubmitted(true);
  };

  useEffect(() => {
    if (status == "authenticated") {
      onFormChange({
        tabIndex: 0,
        fieldName: "loginStatus",
        value: true,
      });
      onFormChange({
        tabIndex: 1,
        fieldName: "fullName",
        value: data?.user?.name ?? "",
      });

      if (currentTab == 0) {
        setCurrentTab(1);
      }
    } else {
      status !== "loading" && resetForm();
    }
  }, [status]);

  return (
    <div className="w-full max-w-7xl mx-2 overflow-hidden rounded-xl bg-white shadow-[0px_2px_8.9px_0px_rgba(0,0,0,0.25)] mb-[3rem]">
      <div className="flex flex-col lg:flex-row">
        <div className="w-full lg:w-1/2 relative">
          <StepperForm
            initialFormState={formState}
            schema={formSchema}
            tabSchemas={tabSchemas}
            onSubmit={handleSubmit}
            className="relative"
            onFormStateChange={setFormState}
            currentTab={currentTab}
            onTabChange={setCurrentTab}
          >
            <div className="sticky top-0 z-10 bg-white">
              <div className="p-2 pb-0">
                <Tabs className="mb-0">
                  <Tab
                    clickDisabled={status == "authenticated" ? true : false}
                    index={0}
                  >
                    Login
                  </Tab>
                  <Tab index={1}>Account Information</Tab>
                  <Tab index={2}>Bank Details</Tab>
                  <Tab index={3}>Password Creation</Tab>
                </Tabs>
              </div>
            </div>

            <div className="max-h-[calc(100vh-20rem)] overflow-y-auto p-[2rem]">
              <TabContent index={0}>
                <SignInForm redirectTo="/become-a-seller" />
              </TabContent>

              <TabContent index={1}>
                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.1 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={1}
                    fieldName="fullName"
                    label="Full Name"
                    placeholder="Enter Full name"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.2 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={1}
                    fieldName="email"
                    label="Email"
                    placeholder="Enter Mail id"
                    type="email"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.3 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={1}
                    fieldName="storeName"
                    label="Store Name"
                    placeholder="Enter Store Name"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.4 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={1}
                    fieldName="storeDescription"
                    label="Store Description"
                    placeholder="Enter Store Description"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={1}
                    fieldName="gstn"
                    label="GSTN Number"
                    placeholder="Enter GSTN No"
                    type="text"
                  />
                </motion.div>

                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.6 }}
                  className="mb-6 text-sm text-gray-700"
                >
                  GSTIN is required to sell products
                </motion.p>

                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.7 }}
                  className="mb-8 flex items-start"
                >
                  <CustomInput
                    tabIndex={1}
                    fieldName="agreeTerms"
                    type="checkbox"
                  />
                  <label
                    htmlFor="agreeTerms"
                    className="ml-2 text-sm text-gray-700"
                  >
                    By clicking, I agree to make you buy{" "}
                    <Link href="#" className="text-red-600 hover:underline">
                      terms of use & privacy policy
                    </Link>
                  </label>
                </motion.div>
              </TabContent>

              <TabContent index={2}>
                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.1 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={2}
                    fieldName="accountHolderName"
                    label="Account Holder Name"
                    placeholder="Enter Account Holder Name"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.2 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={2}
                    fieldName="accountNumber"
                    label="Account Number"
                    placeholder="Enter Account Number"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.3 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={2}
                    fieldName="bankName"
                    label="Bank Name"
                    placeholder="Enter Bank Name"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.4 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={2}
                    fieldName="ifscCode"
                    label="IFSC Code"
                    placeholder="Enter IFSC Code"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={2}
                    fieldName="branchName"
                    label="Branch Name"
                    placeholder="Enter Branch Name"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.6 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={2}
                    fieldName="accountType"
                    label="Account Type"
                    placeholder="Enter Account Type (Savings/Current)"
                    type="text"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.7 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={2}
                    fieldName="upiId"
                    label="UPI ID"
                    placeholder="Enter UPI ID"
                    type="text"
                  />
                </motion.div>
              </TabContent>

              <TabContent index={3}>
                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.1 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={3}
                    fieldName="password"
                    label="Password"
                    placeholder="Enter Password"
                    type="password"
                  />
                </motion.div>

                <motion.div
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.2 }}
                  className="mb-6"
                >
                  <CustomInput
                    tabIndex={3}
                    fieldName="confirmPassword"
                    label="Confirm Password"
                    placeholder="Confirm Password"
                    type="password"
                  />
                </motion.div>
              </TabContent>
            </div>

            {currentTab !== 0 && (
              <div className="sticky bottom-0 z-10 border-t py-[1rem]">
                <Actions
                  showIcons={true}
                  nextLabel="Next"
                  submitLabel="Register & Continue"
                  className="rounded-lg px-6 py-0 transition-colors"
                />
              </div>
            )}
          </StepperForm>
        </div>

        <div className="hidden bg-gray-100 lg:block lg:w-1/2 rounded-2xl">
          <div className="relative h-full w-full">
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3, duration: 0.5 }}
              className="h-full w-full flex items-center justify-center"
            >
              <Image
                src="/assets/images/become-a-seller/sellerRegstration.png"
                alt="Seller dashboard illustration"
                width={600}
                height={600}
                className="h-auto w-[70%] object-cover"
              />
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
}
