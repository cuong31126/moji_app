import { SignupForm} from "@/components/auth/signup-form"; 
import AuthThemeToggle from "@/components/auth/AuthThemeToggle";

const SignUpPage = () => {
  return (
    <div className="bg-muted min-h-dvh overflow-y-auto bg-gradient-eco px-4 py-6 sm:px-6 md:px-10">
      <AuthThemeToggle />
      <div className="mx-auto flex min-h-[calc(100dvh-3rem)] w-full max-w-sm items-center md:max-w-5xl">
        <SignupForm />
      </div>
    </div>
  );
};

export default SignUpPage ; 



