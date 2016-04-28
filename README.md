# Netfilter

## Example

```go
import (
	"fmt"
	"os"

	"github.com/juli3nk/netfilter/iptables"
)

func main() {
	ipt, err := iptables.New(4, false)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	opts := iptables.ListOptions {
		Chain: "OUTPUT",
		Verbose: true,
		Numeric: true,
		LineNumbers: true,
	}

	rules, err := ipt.List("filter", &opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(rules)
}
```
