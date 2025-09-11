import { useEffect, useMemo, useState } from "react";

export const useScreenSize = () => {
  const [size, setSize] = useState<{ width: number; height: number }>({
    width: 1024,
    height: 1024,
  });

  useEffect(() => {
    const handler = () =>
      setSize({ width: window.innerWidth, height: window.innerHeight });
    window.addEventListener("resize", handler);
    handler();
    return () => window.removeEventListener("resize", handler);
  }, []);

  return size;
};

export const useIsMobile = () => {
  const size = useScreenSize();
  return useMemo(() => size.width < 1023, [size.width]);
};
