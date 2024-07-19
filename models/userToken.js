const { Schema, model, Types } = require("mongoose");
const userTokenSchema = new Schema(
  {
    userId: {
      type: Types.ObjectId,
      required: true,
    },
    token: {
      type: String,
      require: true,
    },
  },
  { timestamps: true }
);

const userTokenModel = model("userToken", userTokenSchema);
module.exports = { userTokenModel };
