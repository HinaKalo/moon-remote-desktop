import { describe, expect, it } from "vitest";
import { videoPoint } from "./viewer-session";

describe("fullscreen pointer coordinates", () => {
  it("ignores side bars and maps the visible 4:3 image in a 16:9 window", () => {
    expect(videoPoint(100,100,1920,1080,1024,768,false)).toBeNull();
    expect(videoPoint(240,0,1920,1080,1024,768,false)).toEqual({x:0,y:0});
    expect(videoPoint(960,540,1920,1080,1024,768,false)).toEqual({x:32768,y:32768});
  });
  it("releases a drag on the nearest video edge in a portrait window", () => {
    expect(videoPoint(360,0,720,1280,1920,1080,false)).toBeNull();
    expect(videoPoint(360,0,720,1280,1920,1080,true)).toEqual({x:32768,y:0});
  });
});
