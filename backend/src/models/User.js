import mongoose from "mongoose";

const authProviderSchema = new mongoose.Schema(
  {
    provider: {
      type: String,
      enum: ["local", "google", "github", "facebook"],
      required: true,
    },
    providerId: {
      type: String,
      required: true,
    },
  },
  {
    _id: false,
  }
);

const userSchema = new mongoose.Schema({
    username : {
        type : String  , 
        required : true  , 
        unique : true  , 
        trim : true , 
        lowercase : true ,
    } , 
    hashedPassword : {
        type : String ,
    }, 
    email : {
        type :String ,
        required : true , 
        unique : true ,
        lowercase : true , 
        trim : true,
    }, 
    displayName : {
        type : String , 
        required : true , 
        trim : true,
    },
    avatarUrl : {
        type : String ,
    }, 
    avatarId : {
        type : String , 
    },
    bio : {
        type : String ,
        maxlength : 500 , 
    },
    phone : {
        type : String ,
        sparse : true ,
    },
    authProviders: {
        type: [authProviderSchema],
        default: [],
    },
    

    }, 
    {
    timestamps : true , 

    }
); 

userSchema.index(
    { "authProviders.provider": 1, "authProviders.providerId": 1 },
    { sparse: true }
);

const User = mongoose.model("User" , userSchema); 
export default User ; 
