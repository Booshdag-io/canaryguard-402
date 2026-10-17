async function inspectBlockscout() {
  const url = "https://base.blockscout.com/api/v2/addresses/0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1/token-transfers?type=ERC-20";
  const res = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0", Accept: "application/json" } });
  const data: any = await res.json();
  console.log("Item count:", data.items?.length);
  if (data.items?.length > 0) {
    console.log("Sample item 0:", JSON.stringify(data.items[0], null, 2));
    console.log("Sample item 1:", JSON.stringify(data.items[1], null, 2));
  }
}
inspectBlockscout();
