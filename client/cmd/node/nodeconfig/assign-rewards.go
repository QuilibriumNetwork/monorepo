package nodeconfig

// TODO: Implement a command to assign a config's rewards to a config's rewards address
// Should be able to assign to a specific address or by name of a config directory
// e.g. qclient node config assign-rewards my-config my-throwaway-config
// this finds the address from my-throwaway-config and assigns it to my-config
// qlient node config assign-rewards my-config --reset will reset the rewards address to the default address
// or
// qclient node config assign-rewards my-config --address 0x1234567890abcdef1234567890abcdef1234567890abcdef
//
// If no address is provided, the command will prompt for an address
// the prompt should prompt clearly the user for each part, asking if
// the user wants to use one of the config files as the source of the address
// or if they want to enter a new address manually
// if no configs are found locally, it should prompt the user to create a new config
// or import one

// i.e. Which config do you want to re-assign rewards?
// (1) my-config
// (2) my-other-config
// (3) my-throwaway-config
//
// Enter the number of the config you want to re-assign rewards: 1
// Finding address from my-config...
// Successfully found address 0x1234567890abcdef1234567890abcdef1234567890abcdef
// Which reward address do you want to assign to my-config?
// (1) my-other-config
// (2) my-throwaway-config
// (3) Enter a new address manually
// (4) Reset to default address
//
// Enter the number of the reward address you want to assign: 2
//
// Finding address from my-throwaway-config...
// Successfully found address 0x1234567890abcdef1234567890abcdef1234567890abcdef
// Assigning rewards from my-config to my-throwaway-config
// Successfully assigned rewards.
//
// Summary:
// Node address: 0x1234567890abcdef1234567890abcdef1234567890abcdef
// Rewards address: 0x1234567890abcdef1234567890abcdef1234567890abcdef
//
// Successfully updated my-config
