"use client";

import Link from "next/link";
import { useSession } from "./use-session";
import { AccountMenu } from "./account-menu";

// Top-right landing nav, adapts to auth state.
export function AuthNav() {
  const { loaded, loggedIn, email } = useSession();

  if (loaded && loggedIn) {
    return (
      <div className="flex items-center gap-4">
        <Link href="/dashboard" className="hidden sm:block text-sm text-[#8A8A8F] hover:text-[#ECECEC] transition-colors">
          Dashboard
        </Link>
        <AccountMenu email={email} />
      </div>
    );
  }

  return (
    <div className="flex items-center gap-4">
      <Link href="/login" className="hidden sm:block text-sm text-[#8A8A8F] hover:text-[#ECECEC] transition-colors">Sign in</Link>
      <Link href="/signup" className="text-sm bg-[#E5392B] text-white px-4 py-2 rounded-md font-medium hover:bg-[#cf3325] transition-colors">
        Get API key
      </Link>
    </div>
  );
}

// Hero primary CTA, "Go to dashboard" when signed in, else "Get your API key".
export function HeroCTA() {
  const { loaded, loggedIn } = useSession();
  return (
    <div className="flex items-center justify-center gap-3 mb-20">
      {loaded && loggedIn ? (
        <Link href="/dashboard" className="bg-[#E5392B] text-white px-6 py-3 rounded-md text-sm font-semibold hover:bg-[#cf3325] transition-colors">
          Go to dashboard
        </Link>
      ) : (
        <Link href="/signup" className="bg-[#E5392B] text-white px-6 py-3 rounded-md text-sm font-semibold hover:bg-[#cf3325] transition-colors">
          Get your API key
        </Link>
      )}
      <Link href="/docs" className="border border-[#1E1E20] text-[#ECECEC] px-6 py-3 rounded-md text-sm font-medium hover:border-[#33333A] transition-colors">
        Read the docs
      </Link>
    </div>
  );
}
