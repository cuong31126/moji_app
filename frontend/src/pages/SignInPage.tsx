import { SigninForm} from "@/components/auth/signin-form"; 
import AuthThemeToggle from "@/components/auth/AuthThemeToggle";

const SignInPage = () => {
  return (
    <div className="bg-muted min-h-dvh overflow-y-auto bg-gradient-eco px-4 py-6 sm:px-6 md:px-10">
      <AuthThemeToggle />
      <div className="mx-auto flex min-h-[calc(100dvh-3rem)] w-full max-w-sm items-center md:max-w-5xl">
        <SigninForm />
      </div>
    </div>
  );
};

export default SignInPage ; 



