import { friendService } from "@/services/friendService";
import type { FriendState } from "@/types/store";
import { create } from "zustand";

export const useFriendStore = create<FriendState>((set, get) => ({
  friends: [],
  loading: false,
  receivedList: [],
  sentList: [],

  searchByUsername: async (username) => {
    try {
      set({ loading: true });
      return await friendService.searchByUsername(username);
    } catch (error) {
      console.error("Error while searching user by username", error);
      throw error;
    } finally {
      set({ loading: false });
    }
  },

  addFriend: async (to, message) => {
    try {
      set({ loading: true });
      const result = await friendService.sendFriendRequest(to, message);

      try {
        const requests = await friendService.getAllFriendRequest();
        if (requests) {
          set({ receivedList: requests.received, sentList: requests.sent });
        }
      } catch (error) {
        console.error("Error while refreshing friend requests", error);
      }

      if (result.newFriend) {
        set((state) => ({
          friends: state.friends.some((friend) => friend._id === result.newFriend._id)
            ? state.friends
            : [...state.friends, result.newFriend],
        }));
      }

      return result.message;
    } catch (error) {
      console.error("Error while sending friend request", error);
      throw error;
    } finally {
      set({ loading: false });
    }
  },

  getAllFriendRequests: async () => {
    try {
      set({ loading: true });
      const result = await friendService.getAllFriendRequest();

      if (!result) return;

      const { received, sent } = result;
      set({ receivedList: received, sentList: sent });
    } catch (error) {
      console.error("Error while loading friend requests", error);
      throw error;
    } finally {
      set({ loading: false });
    }
  },

  acceptRequest: async (requestId) => {
    try {
      set({ loading: true });
      const acceptedRequest = get().receivedList.find(
        (request) => request._id === requestId
      );
      const newFriend = await friendService.acceptRequest(requestId);
      const acceptedFriend = newFriend || acceptedRequest?.from;

      set((state) => ({
        receivedList: state.receivedList.filter((request) => request._id !== requestId),
        friends:
          acceptedFriend &&
          !state.friends.some((friend) => friend._id === acceptedFriend._id)
            ? [...state.friends, acceptedFriend]
            : state.friends,
      }));

      try {
        const [requests, friends] = await Promise.all([
          friendService.getAllFriendRequest(),
          friendService.getFriendList(),
        ]);

        if (requests) {
          set({ receivedList: requests.received, sentList: requests.sent });
        }

        set({ friends });
      } catch (error) {
        console.error("Error while refreshing friends after accepting request", error);
      }
    } catch (error) {
      console.error("Error while accepting friend request", error);
      throw error;
    } finally {
      set({ loading: false });
    }
  },

  declineRequest: async (requestId) => {
    try {
      set({ loading: true });
      await friendService.declineRequest(requestId);

      set((state) => ({
        receivedList: state.receivedList.filter((request) => request._id !== requestId),
      }));
    } catch (error) {
      console.error("Error while declining friend request", error);
      throw error;
    } finally {
      set({ loading: false });
    }
  },

  withdrawRequest: async (requestId) => {
    try {
      set({ loading: true });
      await friendService.withdrawRequest(requestId);

      set((state) => ({
        sentList: state.sentList.filter((request) => request._id !== requestId),
      }));
    } catch (error) {
      console.error("Error while withdrawing friend request", error);
      throw error;
    } finally {
      set({ loading: false });
    }
  },

  getFriends: async () => {
    try {
      set({ loading: true });
      const friends = await friendService.getFriendList();
      set({ friends });
    } catch (error) {
      console.error("Error while loading friends", error);
      set({ friends: [] });
    } finally {
      set({ loading: false });
    }
  },
}));
