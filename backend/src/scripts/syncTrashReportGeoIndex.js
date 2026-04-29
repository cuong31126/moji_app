import mongoose from "mongoose";
import TrashReport from "../models/TrashReport.js";
import { getMongoUri } from "../config/env.js";

const isFiniteNumber = (value) => Number.isFinite(Number(value));

const isValidLngLat = (lng, lat) =>
  isFiniteNumber(lng) &&
  isFiniteNumber(lat) &&
  Number(lng) >= -180 &&
  Number(lng) <= 180 &&
  Number(lat) >= -90 &&
  Number(lat) <= 90;

const normalizeLocation = (report) => {
  const location = report.location;

  if (
    location?.type === "Point" &&
    Array.isArray(location.coordinates) &&
    isValidLngLat(location.coordinates[0], location.coordinates[1])
  ) {
    return null;
  }

  const lat = location?.lat ?? report.lat;
  const lng = location?.lng ?? report.lng;

  if (isValidLngLat(lng, lat)) {
    return {
      type: "Point",
      coordinates: [Number(lng), Number(lat)],
      lat: Number(lat),
      lng: Number(lng),
      address: location?.address || "",
    };
  }

  if (Array.isArray(location) && isValidLngLat(location[1], location[0])) {
    return {
      type: "Point",
      coordinates: [Number(location[1]), Number(location[0])],
      lat: Number(location[0]),
      lng: Number(location[1]),
      address: "",
    };
  }

  return false;
};

const run = async () => {
  const mongoUri = getMongoUri();

  if (!mongoUri) {
    throw new Error("Missing MONGODB_URI or MONGODB_CONNECTIONSTRING");
  }

  await mongoose.connect(mongoUri);

  let fixed = 0;
  let skipped = 0;
  const operations = [];

  const cursor = TrashReport.collection.find(
    {},
    { projection: { location: 1, lat: 1, lng: 1 } }
  );

  for await (const report of cursor) {
    const normalizedLocation = normalizeLocation(report);

    if (normalizedLocation === null) {
      continue;
    }

    if (normalizedLocation === false) {
      skipped += 1;
      operations.push({
        updateOne: {
          filter: { _id: report._id },
          update: { $unset: { location: "" } },
        },
      });
      continue;
    }

    fixed += 1;
    operations.push({
      updateOne: {
        filter: { _id: report._id },
        update: { $set: { location: normalizedLocation } },
      },
    });

    if (operations.length >= 500) {
      await TrashReport.collection.bulkWrite(operations);
      operations.length = 0;
    }
  }

  if (operations.length > 0) {
    await TrashReport.collection.bulkWrite(operations);
  }

  const droppedIndexes = await TrashReport.syncIndexes();

  console.log(
    `TrashReport geo migration done. fixed=${fixed}, skipped=${skipped}, droppedIndexes=${JSON.stringify(
      droppedIndexes
    )}`
  );

  await mongoose.disconnect();
};

run().catch(async (error) => {
  console.error("TrashReport geo migration failed", error);
  await mongoose.disconnect();
  process.exit(1);
});
