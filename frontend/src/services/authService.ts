import api from "@/lib/axios";
import type { User } from "@/types/user";

interface AuthResponse {
  accessToken: string;
  user: User;
}

export const authService  = {
    signUp : async ( 
        username : string , 
        password : string , 
        email : string ,
        firstName : string , 
        lastName : string 
    )  =>{
        const res = await api.post("/auth/signup" , {username , password, email ,firstName, lastName  });

        return res.data ; 
    }, 

    signIn: async (username: string, password: string) => {
    const res = await api.post<AuthResponse>("/auth/signin", { username, password });
    return res.data;
    },

    signOut: async () => {
    return api.post("/auth/signout");
    },

    fetchMe: async () => {
    const res = await api.get("/users/me");
    return res.data.user;
    },

    refresh: async () => {
    const res = await api.post<AuthResponse>("/auth/refresh");
    return res.data;
    },
};
